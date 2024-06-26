// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osdiag

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/dblohm7/wingoes/pe"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/authenticode"
)

const (
	maxBinaryValueLen  = 128   // we'll truncate any binary values longer than this
	maxRegValueNameLen = 16384 // maximum length supported by Windows + 1
	initialValueBufLen = 80    // large enough to contain a stringified GUID encoded as UTF-16
)

func logSupportInfo(logf logger.Logf, reason LogSupportInfoReason) {
	var b strings.Builder
	if err := getSupportInfo(&b, reason); err != nil {
		logf("error encoding support info: %v", err)
		return
	}
	logf("%s", b.String())
}

const (
	supportInfoKeyModules  = "modules"
	supportInfoKeyRegistry = "registry"
)

func getSupportInfo(w io.Writer, reason LogSupportInfoReason) error {
	output := make(map[string]any)

	regInfo, err := getRegistrySupportInfo(registry.LOCAL_MACHINE, []string{`SOFTWARE\Policies\Tailscale`, winutil.RegBase})
	if err == nil {
		output[supportInfoKeyRegistry] = regInfo
	} else {
		output[supportInfoKeyRegistry] = err
	}

	if reason == LogSupportInfoReasonBugReport {
		modInfo, err := getModuleInfo()
		if err == nil {
			output[supportInfoKeyModules] = modInfo
		} else {
			output[supportInfoKeyModules] = err
		}
	}

	enc := json.NewEncoder(w)
	return enc.Encode(output)
}

type getRegistrySupportInfoBufs struct {
	nameBuf  []uint16
	valueBuf []byte
}

func getRegistrySupportInfo(root registry.Key, subKeys []string) (map[string]any, error) {
	bufs := getRegistrySupportInfoBufs{
		nameBuf:  make([]uint16, maxRegValueNameLen),
		valueBuf: make([]byte, initialValueBufLen),
	}

	output := make(map[string]any)

	for _, subKey := range subKeys {
		if err := getRegSubKey(root, subKey, 5, &bufs, output); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return nil, fmt.Errorf("getRegistrySupportInfo: %w", err)
		}
	}

	return output, nil
}

func keyString(key registry.Key, subKey string) string {
	var keyStr string
	switch key {
	case registry.CLASSES_ROOT:
		keyStr = `HKCR\`
	case registry.CURRENT_USER:
		keyStr = `HKCU\`
	case registry.LOCAL_MACHINE:
		keyStr = `HKLM\`
	case registry.USERS:
		keyStr = `HKU\`
	case registry.CURRENT_CONFIG:
		keyStr = `HKCC\`
	case registry.PERFORMANCE_DATA:
		keyStr = `HKPD\`
	default:
	}

	return keyStr + subKey
}

func getRegSubKey(key registry.Key, subKey string, recursionLimit int, bufs *getRegistrySupportInfoBufs, output map[string]any) error {
	keyStr := keyString(key, subKey)
	k, err := registry.OpenKey(key, subKey, registry.READ)
	if err != nil {
		return fmt.Errorf("opening %q: %w", keyStr, err)
	}
	defer k.Close()

	kv := make(map[string]any)
	index := uint32(0)

loopValues:
	for {
		nbuf := bufs.nameBuf
		nameLen := uint32(len(nbuf))
		valueType := uint32(0)
		vbuf := bufs.valueBuf
		valueLen := uint32(len(vbuf))

		err := regEnumValue(k, index, &nbuf[0], &nameLen, nil, &valueType, &vbuf[0], &valueLen)
		switch err {
		case windows.ERROR_NO_MORE_ITEMS:
			break loopValues
		case windows.ERROR_MORE_DATA:
			bufs.valueBuf = make([]byte, valueLen)
			continue
		case nil:
		default:
			return fmt.Errorf("regEnumValue: %w", err)
		}

		var value any

		switch valueType {
		case registry.SZ, registry.EXPAND_SZ:
			value = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&vbuf[0])))
		case registry.BINARY:
			if valueLen > maxBinaryValueLen {
				valueLen = maxBinaryValueLen
			}
			value = append([]byte{}, vbuf[:valueLen]...)
		case registry.DWORD:
			value = binary.LittleEndian.Uint32(vbuf[:4])
		case registry.MULTI_SZ:
			// Adapted from x/sys/windows/registry/(Key).GetStringsValue
			p := (*[1 << 29]uint16)(unsafe.Pointer(&vbuf[0]))[: valueLen/2 : valueLen/2]
			var strs []string
			if len(p) > 0 {
				if p[len(p)-1] == 0 {
					p = p[:len(p)-1]
				}
				strs = make([]string, 0, 5)
				from := 0
				for i, c := range p {
					if c == 0 {
						strs = append(strs, string(utf16.Decode(p[from:i])))
						from = i + 1
					}
				}
			}
			value = strs
		case registry.QWORD:
			value = binary.LittleEndian.Uint64(vbuf[:8])
		default:
			value = fmt.Sprintf("<unsupported value type %d>", valueType)
		}

		kv[windows.UTF16PtrToString(&nbuf[0])] = value
		index++
	}

	if recursionLimit > 0 {
		if sks, err := k.ReadSubKeyNames(0); err == nil {
			for _, sk := range sks {
				if err := getRegSubKey(k, sk, recursionLimit-1, bufs, kv); err != nil {
					return err
				}
			}
		}
	}

	output[keyStr] = kv
	return nil
}

type moduleInfo struct {
	path         string            `json:"-"` // internal use only
	BaseAddress  uintptr           `json:"baseAddress"`
	Size         uint32            `json:"size"`
	DebugInfo    map[string]string `json:"debugInfo,omitempty"` // map for JSON marshaling purposes
	DebugInfoErr error             `json:"debugInfoErr,omitempty"`
	Signature    map[string]string `json:"signature,omitempty"` // map for JSON marshaling purposes
	SignatureErr error             `json:"signatureErr,omitempty"`
	VersionInfo  map[string]string `json:"versionInfo,omitempty"` // map for JSON marshaling purposes
	VersionErr   error             `json:"versionErr,omitempty"`
}

func (mi *moduleInfo) setVersionInfo() {
	vi, err := pe.NewVersionInfo(mi.path)
	if err != nil {
		if !errors.Is(err, pe.ErrNotPresent) {
			mi.VersionErr = err
		}
		return
	}

	info := map[string]string{
		"": vi.VersionNumber().String(),
	}

	ci, err := vi.Field("CompanyName")
	if err == nil {
		info["companyName"] = ci
	}

	mi.VersionInfo = info
}

var errAssertingType = errors.New("asserting DataDirectory type")

func (mi *moduleInfo) setDebugInfo(base uintptr, size uint32) {
	pem, err := pe.NewPEFromBaseAddressAndSize(base, size)
	if err != nil {
		mi.DebugInfoErr = err
		return
	}
	defer pem.Close()

	debugDirAny, err := pem.DataDirectoryEntry(pe.IMAGE_DIRECTORY_ENTRY_DEBUG)
	if err != nil {
		if !errors.Is(err, pe.ErrNotPresent) {
			mi.DebugInfoErr = err
		}
		return
	}

	debugDir, ok := debugDirAny.([]pe.IMAGE_DEBUG_DIRECTORY)
	if !ok {
		mi.DebugInfoErr = errAssertingType
		return
	}

	for _, dde := range debugDir {
		if dde.Type != pe.IMAGE_DEBUG_TYPE_CODEVIEW {
			continue
		}

		cv, err := pem.ExtractCodeViewInfo(dde)
		if err == nil {
			mi.DebugInfo = map[string]string{
				"id":  cv.String(),
				"pdb": strings.ToLower(filepath.Base(cv.PDBPath)),
			}
		} else {
			mi.DebugInfoErr = err
		}

		return
	}
}

func (mi *moduleInfo) setAuthenticodeInfo() {
	certSubject, provenance, err := authenticode.QueryCertSubject(mi.path)
	if err != nil {
		if !errors.Is(err, authenticode.ErrSigNotFound) {
			mi.SignatureErr = err
		}
		return
	}

	sigInfo := map[string]string{
		"subject": certSubject,
	}

	switch provenance {
	case authenticode.SigProvEmbedded:
		sigInfo["provenance"] = "embedded"
	case authenticode.SigProvCatalog:
		sigInfo["provenance"] = "catalog"
	default:
	}

	mi.Signature = sigInfo
}

func getModuleInfo() (map[string]moduleInfo, error) {
	// Take a snapshot of all modules currently loaded into the current process
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	result := make(map[string]moduleInfo)
	me := windows.ModuleEntry32{
		Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{})),
	}

	// Now walk the list
	for merr := windows.Module32First(snap, &me); merr == nil; merr = windows.Module32Next(snap, &me) {
		name := strings.ToLower(windows.UTF16ToString(me.Module[:]))
		path := windows.UTF16ToString(me.ExePath[:])
		base := me.ModBaseAddr
		size := me.ModBaseSize

		entry := moduleInfo{
			path:        path,
			BaseAddress: base,
			Size:        size,
		}

		entry.setVersionInfo()
		entry.setDebugInfo(base, size)
		entry.setAuthenticodeInfo()

		result[name] = entry
	}

	return result, nil
}

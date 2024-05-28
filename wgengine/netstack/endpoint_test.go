// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestEndpointBlockingWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	linkEP := NewEndpoint(1, 1500, "")
	pb1 := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pb1.DecRef()
	pb2 := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pb2.DecRef()
	numWrites := make(chan int, 2)
	go func() {
		bl := stack.PacketBufferList{}
		bl.PushBack(pb1)
		n, err := linkEP.WritePackets(bl)
		if err != nil {
			t.Errorf("expected no error, got %s", err)
		} else {
			pb1.DecRef()
		}
		numWrites <- n
		bl = stack.PacketBufferList{}
		bl.PushBack(pb2)
		n, err = linkEP.WritePackets(bl)
		if err != nil {
			t.Errorf("expected no error, got %s", err)
		} else {
			pb2.DecRef()
		}
		numWrites <- n
	}()

	select {
	case n := <-numWrites:
		if n != 1 {
			t.Fatalf("expected 1 write got %d", n)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for 1st write")
	}

	// second write should block
	select {
	case <-numWrites:
		t.Fatalf("expected write to block")
	case <-time.After(50 * time.Millisecond):
		// OK
	}

	pbg := linkEP.ReadContext(ctx)
	if pbg != pb1 {
		t.Fatalf("expected pb1")
	}
	// Read unblocks the 2nd write
	select {
	case n := <-numWrites:
		if n != 1 {
			t.Fatalf("expected 1 write got %d", n)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for 2nd write")
	}
	pbg = linkEP.ReadContext(ctx)
	if pbg != pb2 {
		t.Fatalf("expected pb2")
	}
}

func TestEndpointCloseUnblocksWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	linkEP := NewEndpoint(1, 1500, "")
	pb1 := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	pb2 := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pb2.DecRef()
	numWrites := make(chan int, 2)
	errors := make(chan tcpip.Error, 1)
	go func() {
		bl := stack.PacketBufferList{}
		bl.PushBack(pb1)
		n, err := linkEP.WritePackets(bl)
		if err != nil {
			t.Errorf("expected no error, got %s", err)
		} else {
			pb1.DecRef()
		}
		numWrites <- n
		bl = stack.PacketBufferList{}
		bl.PushBack(pb2)
		n, err = linkEP.WritePackets(bl)
		numWrites <- n
		errors <- err
	}()

	select {
	case n := <-numWrites:
		if n != 1 {
			t.Fatalf("expected 1 write got %d", n)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for 1st write")
	}

	// second write should block
	select {
	case <-numWrites:
		t.Fatalf("expected write to block")
	case <-time.After(50 * time.Millisecond):
		// OK
	}

	// close must unblock pending writes without deadlocking
	linkEP.Close()
	select {
	case n := <-numWrites:
		if n != 0 {
			t.Fatalf("expected 0 writes got %d", n)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for 2nd write num")
	}
	select {
	case err := <-errors:
		if _, ok := err.(*tcpip.ErrClosedForSend); !ok {
			t.Fatalf("expected ErrClosedForSend got %s", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out for 2nd write error")
	}
}

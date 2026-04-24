package netns

import (
	"testing"
)

func TestShouldBindToDefaultInterface(t *testing.T) {
	logf := t.Logf

	tests := []struct {
		name      string
		address   string
		isolation bool
		want      bool
	}{
		{
			name:      "localhost_always_false",
			address:   "127.0.0.1:80",
			isolation: false,
			want:      false,
		},
		{
			name:      "public_ip_no_isolation",
			address:   "8.8.8.8:53",
			isolation: false,
			want:      true,
		},
		{
			name:      "coder_ip_with_isolation",
			address:   "[fd60:627a:a42b::1]:443",
			isolation: true,
			want:      true,
		},
		{
			name:      "public_ip_with_isolation",
			address:   "8.8.8.8:53",
			isolation: true,
			want:      false,
		},
		{
			name:      "tailscale_ula_with_isolation",
			address:   "[fd7a:115c:a1e0::1]:443",
			isolation: true,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coderSoftIsolation.Store(tt.isolation)
			t.Cleanup(func() { coderSoftIsolation.Store(false) })

			got := shouldBindToDefaultInterface(logf, tt.address)
			if got != tt.want {
				t.Errorf("shouldBindToDefaultInterface(%q) with isolation=%v = %v, want %v",
					tt.address, tt.isolation, got, tt.want)
			}
		})
	}
}

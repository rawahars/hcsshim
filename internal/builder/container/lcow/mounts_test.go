//go:build windows && lcow

package lcow

import (
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// ─────────────────────────────────────────────────────────────────────────────
// parseExtensibleVirtualDiskPath
// ─────────────────────────────────────────────────────────────────────────────

// TestParseExtensibleVirtualDiskPath verifies parsing of EVD URIs into
// provider type and source path, including error cases.
func TestParseExtensibleVirtualDiskPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		wantType       string
		wantSourcePath string
		wantErr        bool
	}{
		{
			name:           "valid path",
			input:          "evd://mytype/some/path/disk.vhdx",
			wantType:       "mytype",
			wantSourcePath: "some/path/disk.vhdx",
		},
		{
			name:    "missing evd:// prefix",
			input:   "notevd://type/path",
			wantErr: true,
		},
		{
			name:    "no type/path separator",
			input:   "evd://typeonly",
			wantErr: true,
		},
		{
			name:    "empty type",
			input:   "evd:///path",
			wantErr: true,
		},
		{
			name:           "empty source path is accepted",
			input:          "evd://mytype/",
			wantType:       "mytype",
			wantSourcePath: "",
		},
		{
			name:           "source path can start with slash",
			input:          "evd://mytype//disk.vhdx",
			wantType:       "mytype",
			wantSourcePath: "/disk.vhdx",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			evdType, sourcePath, err := parseExtensibleVirtualDiskPath(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if evdType != tt.wantType {
				t.Errorf("expected EVD type %q, got %q", tt.wantType, evdType)
			}
			if sourcePath != tt.wantSourcePath {
				t.Errorf("expected source path %q, got %q", tt.wantSourcePath, sourcePath)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateHugePageMount
// ─────────────────────────────────────────────────────────────────────────────

// TestValidateHugePageMount verifies validation of hugepages mount sources,
// including supported/unsupported sizes and malformed paths.
func TestValidateHugePageMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  string
		wantErr bool
	}{
		{name: "valid 2M", source: "hugepages://2M/location", wantErr: false},
		{name: "valid 2M nested location", source: "hugepages://2M/a/b/c", wantErr: false},
		{name: "unsupported size 1G", source: "hugepages://1G/location", wantErr: true},
		{name: "missing subdirectories", source: "hugepages://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateHugePageMount(tt.source)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// isReadOnlyMount
// ─────────────────────────────────────────────────────────────────────────────

// TestIsReadOnlyMount verifies detection of the "ro" mount option across
// various option slices and casing.
func TestIsReadOnlyMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		options  []string
		expected bool
	}{
		{name: "has ro option", options: []string{"rw", "ro"}, expected: true},
		{name: "case insensitive RO", options: []string{"RO"}, expected: true},
		{name: "no ro option", options: []string{"rw", "noatime"}, expected: false},
		{name: "empty options", options: nil, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mount := &specs.Mount{Options: tt.options}
			if got := isReadOnlyMount(mount); got != tt.expected {
				t.Errorf("isReadOnlyMount(%v) = %v, want %v", tt.options, got, tt.expected)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// isGuestInternalPath
// ─────────────────────────────────────────────────────────────────────────────

// TestIsGuestInternalPath verifies that known guest-internal prefixes are
// detected and regular paths are not.
func TestIsGuestInternalPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{name: "sandbox prefix", path: "sandbox:///a/path", expected: true},
		{name: "sandbox-tmp prefix", path: "sandbox-tmp:///a/path", expected: true},
		{name: "uvm prefix", path: "uvm:///a/path", expected: true},
		{name: "regular host path", path: `/host/data`, expected: false},
		{name: "hugepages prefix", path: "hugepages://2M/loc", expected: false},
		{name: "empty string", path: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isGuestInternalPath(tt.path); got != tt.expected {
				t.Errorf("isGuestInternalPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

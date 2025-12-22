package sandbox_options

import (
	"fmt"
	"strings"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

// -----------------------------------------------------------------------------
// Small utilities to reduce nil-check boilerplate
// -----------------------------------------------------------------------------

func setStr(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func setBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

func setU32(dst *uint32, src *uint32) {
	if src != nil {
		*dst = *src
	}
}

func setU64(dst *uint64, src *uint64) {
	if src != nil {
		*dst = *src
	}
}

func copyU32(in []uint32) []uint32 {
	out := make([]uint32, len(in))
	copy(out, in)
	return out
}

func copyU64(in []uint64) []uint64 {
	out := make([]uint64, len(in))
	copy(out, in)
	return out
}

func setInt32(dst *int32, src *int32) {
	if src != nil {
		*dst = *src
	}
}

// splitPlatform expects "linux/amd64" or "windows/amd64"
func splitPlatform(p string) (osName, arch string, err error) {
	if p == "" {
		return "", "", fmt.Errorf("sandbox_platform empty; expected \"linux/amd64\" or \"windows/amd64\"")
	}
	parts := strings.Split(p, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid sandbox_platform %q; expected \"linux/amd64\" or \"windows/amd64\"", p)
	}
	return parts[0], parts[1], nil
}

// Map proto RegistryHive -> hcsschema.RegistryHive.
func mapProtoHive(h RegistryHive) hcsschema.RegistryHive {
	switch h {
	case RegistryHive_REGISTRY_HIVE_SYSTEM:
		return hcsschema.RegistryHive_SYSTEM
	case RegistryHive_REGISTRY_HIVE_SOFTWARE:
		return hcsschema.RegistryHive_SOFTWARE
	case RegistryHive_REGISTRY_HIVE_SECURITY:
		return hcsschema.RegistryHive_SECURITY
	case RegistryHive_REGISTRY_HIVE_SAM:
		return hcsschema.RegistryHive_SAM
	default:
		return hcsschema.RegistryHive_SYSTEM
	}
}

// Map proto RegistryValueType -> hcsschema.RegistryValueType.
func mapProtoRegValueType(t RegistryValueType) hcsschema.RegistryValueType {
	switch t {
	case RegistryValueType_REGISTRY_VALUE_TYPE_NONE:
		return hcsschema.RegistryValueType_NONE
	case RegistryValueType_REGISTRY_VALUE_TYPE_STRING:
		return hcsschema.RegistryValueType_STRING
	case RegistryValueType_REGISTRY_VALUE_TYPE_EXPANDED_STRING:
		return hcsschema.RegistryValueType_EXPANDED_STRING
	case RegistryValueType_REGISTRY_VALUE_TYPE_MULTI_STRING:
		return hcsschema.RegistryValueType_MULTI_STRING
	case RegistryValueType_REGISTRY_VALUE_TYPE_BINARY:
		return hcsschema.RegistryValueType_BINARY
	case RegistryValueType_REGISTRY_VALUE_TYPE_D_WORD:
		return hcsschema.RegistryValueType_D_WORD
	case RegistryValueType_REGISTRY_VALUE_TYPE_Q_WORD:
		return hcsschema.RegistryValueType_Q_WORD
	case RegistryValueType_REGISTRY_VALUE_TYPE_CUSTOM_TYPE:
		return hcsschema.RegistryValueType_CUSTOM_TYPE
	default:
		return hcsschema.RegistryValueType_NONE
	}
}

// Map hcsschema.RegistryHive -> proto RegistryHive.
func mapHcsHiveToProto(h hcsschema.RegistryHive) RegistryHive {
	switch h {
	case hcsschema.RegistryHive_SYSTEM:
		return RegistryHive_REGISTRY_HIVE_SYSTEM
	case hcsschema.RegistryHive_SOFTWARE:
		return RegistryHive_REGISTRY_HIVE_SOFTWARE
	case hcsschema.RegistryHive_SECURITY:
		return RegistryHive_REGISTRY_HIVE_SECURITY
	case hcsschema.RegistryHive_SAM:
		return RegistryHive_REGISTRY_HIVE_SAM
	default:
		// Choose a sensible default. SYSTEM matches your proto->HCS default.
		return RegistryHive_REGISTRY_HIVE_SYSTEM
	}
}

// Map hcsschema.RegistryValueType -> proto RegistryValueType.
func mapHcsRegValueTypeToProto(t hcsschema.RegistryValueType) RegistryValueType {
	switch t {
	case hcsschema.RegistryValueType_NONE:
		return RegistryValueType_REGISTRY_VALUE_TYPE_NONE
	case hcsschema.RegistryValueType_STRING:
		return RegistryValueType_REGISTRY_VALUE_TYPE_STRING
	case hcsschema.RegistryValueType_EXPANDED_STRING:
		return RegistryValueType_REGISTRY_VALUE_TYPE_EXPANDED_STRING
	case hcsschema.RegistryValueType_MULTI_STRING:
		return RegistryValueType_REGISTRY_VALUE_TYPE_MULTI_STRING
	case hcsschema.RegistryValueType_BINARY:
		return RegistryValueType_REGISTRY_VALUE_TYPE_BINARY
	case hcsschema.RegistryValueType_D_WORD:
		return RegistryValueType_REGISTRY_VALUE_TYPE_D_WORD
	case hcsschema.RegistryValueType_Q_WORD:
		return RegistryValueType_REGISTRY_VALUE_TYPE_Q_WORD
	case hcsschema.RegistryValueType_CUSTOM_TYPE:
		return RegistryValueType_REGISTRY_VALUE_TYPE_CUSTOM_TYPE
	default:
		return RegistryValueType_REGISTRY_VALUE_TYPE_NONE
	}
}

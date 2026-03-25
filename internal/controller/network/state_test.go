//go:build windows

package network_test

import (
	"testing"

	"github.com/Microsoft/hcsshim/internal/controller/network"
)

func TestStateString(t *testing.T) {
	tests := []struct {
		state network.State
		want  string
	}{
		{network.StateNotConfigured, "NotConfigured"},
		{network.StateConfigured, "Configured"},
		{network.StateInvalid, "Invalid"},
		{network.StateTornDown, "TornDown"},
		{network.State(99), "Unknown"},
		{network.State(-1), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

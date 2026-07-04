package servers

import "testing"

func TestValidAuthType(t *testing.T) {
	tests := []struct {
		in   AuthType
		want bool
	}{
		{AuthKey, true},
		{AuthPassword, true},
		{AuthType("token"), false},
		{AuthType(""), false},
	}
	for _, tt := range tests {
		if got := validAuthType(tt.in); got != tt.want {
			t.Errorf("validAuthType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidServerType(t *testing.T) {
	tests := []struct {
		in   ServerType
		want bool
	}{
		{TypeDockerOnly, true},
		{TypeFull, true},
		{TypeMock, true},
		{ServerType("vm"), false},
		{ServerType(""), false},
	}
	for _, tt := range tests {
		if got := validServerType(tt.in); got != tt.want {
			t.Errorf("validServerType(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidEnvironment(t *testing.T) {
	tests := []struct {
		in   Environment
		want bool
	}{
		{EnvProd, true},
		{EnvStaging, true},
		{EnvDev, true},
		{Environment("qa"), false},
		{Environment(""), false},
	}
	for _, tt := range tests {
		if got := validEnvironment(tt.in); got != tt.want {
			t.Errorf("validEnvironment(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidStatus(t *testing.T) {
	tests := []struct {
		in   Status
		want bool
	}{
		{StatusOnline, true},
		{StatusOffline, true},
		{StatusUnknown, true},
		{Status("degraded"), false},
		{Status(""), false},
	}
	for _, tt := range tests {
		if got := validStatus(tt.in); got != tt.want {
			t.Errorf("validStatus(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "returns API key when authorization header is valid",
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			want:    "abc123",
			wantErr: nil,
		},
		{
			name:    "returns error when authorization header is missing",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "returns error when authorization scheme is incorrect",
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "returns error when authorization header has no key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.want {
				t.Errorf("GetAPIKey() got = %q, want %q", got, tt.want)
			}

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", err)
				}
			} else {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

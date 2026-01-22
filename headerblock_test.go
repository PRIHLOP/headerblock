package headerblock_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	tbua "github.com/PRIHLOP/headerblock"
)

const pluginName = "headerBlock"

type noopHandler struct{}

func (n noopHandler) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusTeapot)
}

type testCase struct {
	name           string
	config         func() *tbua.Config
	headers        map[string]string
	remoteAddr     string
	expectedStatus int
}

func TestHeaderBlock(t *testing.T) {
	tests := []testCase{
		{
			name: "NoHeadersAllowed",
			config: func() *tbua.Config {
				return tbua.CreateConfig()
			},
			expectedStatus: http.StatusTeapot,
		},
		{
			name: "ValidUserAgent",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Name: "User-Agent", Value: "SpamBot"},
				}
				return cfg
			},
			headers: map[string]string{
				"User-Agent": "Mozilla",
			},
			expectedStatus: http.StatusTeapot,
		},
		{
			name: "BlockedUserAgent",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Name: "User-Agent", Value: "Googlebot"},
				}
				return cfg
			},
			headers: map[string]string{
				"User-Agent": "Googlebot",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "WhitelistByHeaderValue",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Name: "Cf-Ipcountry"},
				}
				cfg.WhitelistRequestHeaders = []tbua.HeaderConfig{
					{Name: "Cf-Ipcountry", Value: "VN"},
				}
				return cfg
			},
			headers: map[string]string{
				"Cf-Ipcountry": "VN",
			},
			expectedStatus: http.StatusTeapot,
		},
		{
			name: "WhitelistMismatch",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Name: "Cf-Ipcountry"},
				}
				cfg.WhitelistRequestHeaders = []tbua.HeaderConfig{
					{Name: "Cf-Ipcountry", Value: "VN"},
				}
				return cfg
			},
			headers: map[string]string{
				"Cf-Ipcountry": "FR",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "AllowedIPBypass",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Name: "X-Test"},
				}
				cfg.AllowedIPs = []string{"10.0.0.0/8"}
				return cfg
			},
			headers: map[string]string{
				"X-Test": "blocked",
			},
			remoteAddr:     "10.1.1.1:1234",
			expectedStatus: http.StatusTeapot,
		},
		{
			name: "RegexHeaderAndValue",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Name: "^X-.*", Value: "forbidden|blocked"},
				}
				return cfg
			},
			headers: map[string]string{
				"X-Custom": "blocked-value",
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "ValueOnlyRule",
			config: func() *tbua.Config {
				cfg := tbua.CreateConfig()
				cfg.RequestHeaders = []tbua.HeaderConfig{
					{Value: "evil"},
				}
				return cfg
			},
			headers: map[string]string{
				"Any-Header": "evil-content",
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tbua.New(
				context.Background(),
				noopHandler{},
				tt.config(),
				pluginName,
			)
			if err != nil {
				t.Fatalf("plugin init error: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Fatalf("expected %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

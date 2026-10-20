package s3token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testToken = "build-token-0123456789"

type captured struct {
	req  *http.Request
	hits int
}

func (c *captured) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	c.req = req
	c.hits++
	rw.WriteHeader(http.StatusOK)
}

func newTest(t *testing.T, mutate func(*Config)) (http.Handler, *captured) {
	t.Helper()
	cfg := CreateConfig()
	cfg.Endpoint = "https://s3.example.com"
	cfg.Bucket = "sstate"
	cfg.StripPrefix = "/sstate"
	cfg.AccessKeyID = "AKIDEXAMPLE"
	cfg.SecretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	cfg.Tokens = []string{testToken}
	if mutate != nil {
		mutate(cfg)
	}
	next := &captured{}
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	h.(*tokenS3).now = func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }
	return h, next
}

func do(h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The expected signatures were produced by the AWS SDK for Go v2 signer
// for the same request, credentials and time.
func TestSignatureMatchesAWSSigner(t *testing.T) {
	h, next := newTest(t, nil)
	rec := do(h, "GET", "/sstate/t/"+testToken+"/ab/cd/sstate:foo+bar%201.tar.zst?acl", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	r := next.req
	if r.Host != "s3.example.com" {
		t.Errorf("host %q", r.Host)
	}
	if got, want := r.URL.EscapedPath(), "/sstate/ab/cd/sstate%3Afoo%2Bbar%201.tar.zst"; got != want {
		t.Errorf("path %q, want %q", got, want)
	}
	if r.URL.RawQuery != "" {
		t.Errorf("query %q leaked upstream", r.URL.RawQuery)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261019/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=a9126018bed048523ded7c51fb7319faea10f7a7cf4aa82e3166efd0f0c1f1b5"
	if got := r.Header.Get("Authorization"); got != want {
		t.Errorf("authorization\n got %s\nwant %s", got, want)
	}
}

func TestVirtualHostR2(t *testing.T) {
	h, next := newTest(t, func(c *Config) {
		c.Endpoint = "https://acct.r2.cloudflarestorage.com"
		c.Region = "auto"
		c.VirtualHost = true
		c.StripPrefix = ""
	})
	if rec := do(h, "GET", "/x/y.siginfo", map[string]string{"Authorization": "Bearer " + testToken}); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	r := next.req
	if r.Host != "sstate.acct.r2.cloudflarestorage.com" || r.URL.EscapedPath() != "/x/y.siginfo" {
		t.Fatalf("host %q path %q", r.Host, r.URL.EscapedPath())
	}
	want := "Signature=0d79cb8f506261f799783e299af4c21a623d0da8f078a68c5e2c5ba7c5883309"
	if got := r.Header.Get("Authorization"); got[len(got)-len(want):] != want {
		t.Errorf("authorization %s", got)
	}
}

func TestTokenForms(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
		hdr    map[string]string
		want   int
	}{
		{"path token", "GET", "/sstate/t/" + testToken + "/a/b", nil, 200},
		{"path token HEAD", "HEAD", "/sstate/t/" + testToken + "/a/b", nil, 200},
		{"bearer", "GET", "/sstate/a/b", map[string]string{"Authorization": "Bearer " + testToken}, 200},
		{"basic password", "GET", "/sstate/a/b", map[string]string{"Authorization": basic("yocto", testToken)}, 200},
		{"no token", "GET", "/sstate/a/b", nil, 401},
		{"wrong token", "GET", "/sstate/t/wrong-token-0123456789/a/b", nil, 401},
		{"wrong bearer", "GET", "/sstate/a/b", map[string]string{"Authorization": "Bearer nope"}, 401},
		{"write refused", "PUT", "/sstate/t/" + testToken + "/a/b", nil, 405},
		{"delete refused", "DELETE", "/sstate/t/" + testToken + "/a/b", nil, 405},
		{"outside prefix", "GET", "/other/t/" + testToken + "/a/b", nil, 404},
		{"bucket listing", "GET", "/sstate/t/" + testToken + "/", nil, 404},
		{"directory", "GET", "/sstate/t/" + testToken + "/a/", nil, 404},
		{"token only", "GET", "/sstate/t/" + testToken, nil, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, next := newTest(t, nil)
			rec := do(h, c.method, c.target, c.hdr)
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d", rec.Code, c.want)
			}
			if (next.hits == 1) != (c.want == 200) {
				t.Fatalf("upstream hits %d", next.hits)
			}
		})
	}
}

func TestClientCredentialsAndHeaders(t *testing.T) {
	h, next := newTest(t, nil)
	do(h, "GET", "/sstate/a/b", map[string]string{
		"Authorization":        "Bearer " + testToken,
		"Cookie":               "session=1",
		"X-Amz-Security-Token": "evil",
		"Range":                "bytes=0-9",
		"If-None-Match":        `"abc"`,
	})
	r := next.req
	if r.Header.Get("Cookie") != "" || r.Header.Get("X-Amz-Security-Token") != "" {
		t.Errorf("client headers leaked: %v", r.Header)
	}
	if r.Header.Get("Range") != "bytes=0-9" || r.Header.Get("If-None-Match") != `"abc"` {
		t.Errorf("range/conditional headers dropped: %v", r.Header)
	}
}

func TestKeyPrefix(t *testing.T) {
	h, next := newTest(t, func(c *Config) { c.KeyPrefix = "scarthgap/" })
	do(h, "GET", "/sstate/t/"+testToken+"/a/b", nil)
	if got := next.req.URL.Path; got != "/sstate/scarthgap/a/b" {
		t.Fatalf("path %q", got)
	}
}

func TestSecretsFromFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"ak":     "AKIDEXAMPLE\n",
		"sk":     "secret\n",
		"tokens": "# builds\nfile-token-0123456789\n\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := newTest(t, func(c *Config) {
		c.AccessKeyID = ""
		c.SecretAccessKey = ""
		c.Tokens = []string{}
		c.AccessKeyIDFile = filepath.Join(dir, "ak")
		c.SecretAccessKeyFile = filepath.Join(dir, "sk")
		c.TokensFile = filepath.Join(dir, "tokens")
	})
	if rec := do(h, "GET", "/sstate/t/file-token-0123456789/a", nil); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestConfigErrors(t *testing.T) {
	cases := map[string]func(*Config){
		"no endpoint": func(c *Config) { c.Endpoint = "" },
		"bad scheme":  func(c *Config) { c.Endpoint = "ftp://x" },
		"no bucket":   func(c *Config) { c.Bucket = "" },
		"no secret":   func(c *Config) { c.SecretAccessKey = "" },
		"no tokens":   func(c *Config) { c.Tokens = nil },
		"short token": func(c *Config) { c.Tokens = []string{"short"} },
		"both forms":  func(c *Config) { c.SecretAccessKeyFile = "/x" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.Endpoint = "https://s3.example.com"
			cfg.Bucket = "b"
			cfg.AccessKeyID = "a"
			cfg.SecretAccessKey = "s"
			cfg.Tokens = []string{testToken}
			mutate(cfg)
			if _, err := New(context.Background(), &captured{}, cfg, "t"); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func basic(user, pass string) string {
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

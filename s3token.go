// Package s3token is a Traefik middleware plugin that lets clients
// read objects from an S3-compatible bucket (AWS S3, Cloudflare R2, RustFS,
// MinIO) with one shared token instead of a per-request AWS signature.
//
// It checks the token, turns the request into a plain GetObject/HeadObject
// for the configured bucket, signs it with AWS Signature Version 4 and hands
// it to the next handler, which is the Traefik service pointing at the
// bucket endpoint.
package s3token

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// emptySHA256 is the payload hash of a GET or HEAD request without a body.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// minTokenLen keeps guessable tokens out of the config.
const minTokenLen = 16

// Config is the plugin configuration as written in Traefik's dynamic config.
type Config struct {
	// Endpoint is the bucket server, e.g. https://<account>.r2.cloudflarestorage.com.
	// The Traefik service for this router must point at the same URL.
	Endpoint string `json:"endpoint,omitempty"`
	// Region is the signing region: "auto" for R2, "us-east-1" for most others.
	Region string `json:"region,omitempty"`
	Bucket string `json:"bucket,omitempty"`
	// VirtualHost addresses the bucket as <bucket>.<endpoint host> instead of
	// <endpoint>/<bucket> (path style, the default).
	VirtualHost bool `json:"virtualHost,omitempty"`
	// KeyPrefix is put in front of every object key, e.g. "scarthgap/".
	KeyPrefix string `json:"keyPrefix,omitempty"`
	// StripPrefix is removed from the request path before the key is read,
	// e.g. "/sstate" when the router matches PathPrefix(`/sstate`).
	StripPrefix string `json:"stripPrefix,omitempty"`

	AccessKeyID         string `json:"accessKeyID,omitempty"`
	AccessKeyIDFile     string `json:"accessKeyIDFile,omitempty"`
	SecretAccessKey     string `json:"secretAccessKey,omitempty"`
	SecretAccessKeyFile string `json:"secretAccessKeyFile,omitempty"`

	// Tokens are accepted as a Bearer token, as the Basic auth password, or
	// in the path as /t/<token>/<key>. TokensFile holds one token per line.
	Tokens     []string `json:"tokens,omitempty"`
	TokensFile string   `json:"tokensFile,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{Region: "us-east-1"}
}

type tokenS3 struct {
	next      http.Handler
	name      string
	host      string // host[:port] the request is signed for
	pathBase  string // "/<bucket>" for path style, "" for virtual host
	keyPrefix string
	strip     string
	region    string
	accessKey string
	secretKey string
	tokens    [][32]byte // SHA-256 of each accepted token
	now       func() time.Time
}

// New creates the middleware from its configuration.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%s: endpoint must be an http(s) URL, got %q", name, cfg.Endpoint)
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("%s: bucket is required", name)
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	accessKey, err := valueOrFile(cfg.AccessKeyID, cfg.AccessKeyIDFile)
	if err != nil {
		return nil, fmt.Errorf("%s: access key: %w", name, err)
	}
	secretKey, err := valueOrFile(cfg.SecretAccessKey, cfg.SecretAccessKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: secret key: %w", name, err)
	}
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("%s: accessKeyID and secretAccessKey are required", name)
	}
	raw := append([]string{}, cfg.Tokens...)
	if cfg.TokensFile != "" {
		b, err := os.ReadFile(cfg.TokensFile)
		if err != nil {
			return nil, fmt.Errorf("%s: tokens file: %w", name, err)
		}
		raw = append(raw, strings.Split(string(b), "\n")...)
	}
	var tokens [][32]byte
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if len(t) < minTokenLen {
			return nil, fmt.Errorf("%s: tokens must be at least %d characters", name, minTokenLen)
		}
		tokens = append(tokens, sha256.Sum256([]byte(t)))
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%s: at least one token is required", name)
	}

	m := &tokenS3{
		next:      next,
		name:      name,
		host:      u.Host,
		pathBase:  "/" + cfg.Bucket,
		keyPrefix: strings.TrimPrefix(cfg.KeyPrefix, "/"),
		strip:     strings.TrimSuffix(cfg.StripPrefix, "/"),
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
		tokens:    tokens,
		now:       time.Now,
	}
	if cfg.VirtualHost {
		m.host = cfg.Bucket + "." + u.Host
		m.pathBase = ""
	}
	return m, nil
}

func valueOrFile(value, file string) (string, error) {
	if file == "" {
		return strings.TrimSpace(value), nil
	}
	if value != "" {
		return "", errors.New("set either the value or the file, not both")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (m *tokenS3) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		rw.Header().Set("Allow", "GET, HEAD")
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p := req.URL.Path
	if m.strip != "" {
		if p != m.strip && !strings.HasPrefix(p, m.strip+"/") {
			http.NotFound(rw, req)
			return
		}
		p = strings.TrimPrefix(p, m.strip)
	}

	token := ""
	if rest := strings.TrimPrefix(p, "/t/"); rest != p {
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			http.NotFound(rw, req)
			return
		}
		token, p = rest[:i], rest[i:]
	} else if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	} else if _, pass, ok := req.BasicAuth(); ok {
		token = pass
	}
	if !m.validToken(token) {
		rw.Header().Set("WWW-Authenticate", `Basic realm="s3"`)
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}

	key := strings.TrimPrefix(p, "/")
	if !validKey(key) {
		http.NotFound(rw, req)
		return
	}
	key = m.keyPrefix + key

	// Only the object itself is reachable: no query (ACLs, listings, other
	// sub-resources) and none of the client's credentials go upstream.
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	for h := range req.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-amz-") {
			req.Header.Del(h)
		}
	}
	req.URL.RawQuery = ""
	req.URL.Path = m.pathBase + "/" + key
	req.URL.RawPath = m.pathBase + "/" + uriEncodePath(key)
	req.RequestURI = req.URL.RequestURI()
	req.Host = m.host

	m.sign(req)
	m.next.ServeHTTP(rw, req)
}

func (m *tokenS3) validToken(token string) bool {
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	ok := 0
	for i := range m.tokens {
		ok |= subtle.ConstantTimeCompare(sum[:], m.tokens[i][:])
	}
	return ok == 1
}

// validKey rejects empty keys, "directories" and dot segments.
func validKey(key string) bool {
	if key == "" || strings.HasSuffix(key, "/") {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// sign adds an AWS Signature Version 4 Authorization header for service s3.
func (m *tokenS3) sign(req *http.Request) {
	t := m.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", emptySHA256)

	headers := map[string]string{
		"host":                 req.Host,
		"x-amz-content-sha256": emptySHA256,
		"x-amz-date":           amzDate,
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonical := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"", // no query string
		canonHeaders.String(),
		signedHeaders,
		emptySHA256,
	}, "\n")

	scope := day + "/" + m.region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])

	k := hmacSHA256([]byte("AWS4"+m.secretKey), day)
	k = hmacSHA256(k, m.region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+m.accessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+sig)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// uriEncodePath encodes each segment the way S3 expects in the canonical
// request: everything but unreserved characters is percent-encoded, and the
// slashes between segments stay as they are.
func uriEncodePath(p string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '/' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

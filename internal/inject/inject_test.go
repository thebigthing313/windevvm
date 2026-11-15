package inject

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"windevvm/internal/secrets"
)

const (
	ghPH  = "wdvm_ph_GITHUB_TOKEN_00000000000000000000000000000001"
	ghVal = "ghp_REALTOKENVALUE"
	aiPH  = "wdvm_ph_ANTHROPIC_API_KEY_00000000000000000000000000000002"
	aiVal = "sk-ant-REALKEY"
)

func testInjector(t *testing.T) *Injector {
	t.Helper()
	in, err := New([]Binding{
		{Placeholder: ghPH, Secret: secrets.Secret{Name: "GITHUB_TOKEN", Hosts: []string{"github.com", "api.github.com"}, Value: []byte(ghVal)}},
		{Placeholder: aiPH, Secret: secrets.Secret{Name: "ANTHROPIC_API_KEY", Hosts: []string{"api.anthropic.com"}, In: []secrets.Location{secrets.InHeader, secrets.InBody, secrets.InURL}, Value: []byte(aiVal)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestHeaderInjection(t *testing.T) {
	in := testInjector(t)
	r := httptest.NewRequest("GET", "https://api.github.com/user", nil)
	r.Header.Set("Authorization", "Bearer "+ghPH)
	used, err := in.RewriteRequest(r, "api.github.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+ghVal {
		t.Fatalf("Authorization = %q", got)
	}
	if len(used) != 1 || used[0] != "GITHUB_TOKEN" {
		t.Fatalf("used = %v", used)
	}
}

func TestBasicAuthInjection(t *testing.T) {
	in := testInjector(t)
	r := httptest.NewRequest("GET", "https://github.com/me/repo.git/info/refs", nil)
	r.SetBasicAuth("x-access-token", ghPH)
	if _, err := in.RewriteRequest(r, "github.com", true); err != nil {
		t.Fatal(err)
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != "x-access-token" || pass != ghVal {
		t.Fatalf("BasicAuth = %q %q %v", user, pass, ok)
	}
}

func TestViolations(t *testing.T) {
	in := testInjector(t)
	cases := []struct {
		name   string
		build  func() *http.Request
		host   string
		secure bool
	}{
		{"unbound host", func() *http.Request {
			r := httptest.NewRequest("GET", "https://evil.test/", nil)
			r.Header.Set("X-Token", ghPH)
			return r
		}, "evil.test", true},
		{"plain http", func() *http.Request {
			r := httptest.NewRequest("GET", "http://api.github.com/", nil)
			r.Header.Set("Authorization", "Bearer "+ghPH)
			return r
		}, "api.github.com", false},
		{"basic to unbound host", func() *http.Request {
			r := httptest.NewRequest("GET", "https://evil.test/", nil)
			r.SetBasicAuth("u", ghPH)
			return r
		}, "evil.test", true},
		{"body location not allowed", func() *http.Request {
			return httptest.NewRequest("POST", "https://api.github.com/x", strings.NewReader(`{"t":"`+ghPH+`"}`))
		}, "api.github.com", true},
		{"query location not allowed", func() *http.Request {
			return httptest.NewRequest("GET", "https://api.github.com/x?token="+ghPH, nil)
		}, "api.github.com", true},
		{"other secret's host", func() *http.Request {
			r := httptest.NewRequest("GET", "https://api.github.com/", nil)
			r.Header.Set("X-Api-Key", aiPH)
			return r
		}, "api.github.com", true},
	}
	for _, c := range cases {
		_, err := in.RewriteRequest(c.build(), c.host, c.secure)
		var v *Violation
		if !errors.As(err, &v) {
			t.Errorf("%s: expected a Violation, got %v", c.name, err)
		}
	}
}

func TestBodyAndURLInjection(t *testing.T) {
	in := testInjector(t)
	r := httptest.NewRequest("POST", "https://api.anthropic.com/v1/x/"+aiPH+"?key="+aiPH, strings.NewReader(`{"key":"`+aiPH+`"}`))
	if _, err := in.RewriteRequest(r, "api.anthropic.com", true); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != `{"key":"`+aiVal+`"}` {
		t.Fatalf("body = %s", body)
	}
	if r.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", r.ContentLength, len(body))
	}
	if r.URL.Query().Get("key") != aiVal || r.URL.Path != "/v1/x/"+aiVal {
		t.Fatalf("URL = %s", r.URL)
	}
}

func TestNoPlaceholderUntouched(t *testing.T) {
	in := testInjector(t)
	r := httptest.NewRequest("POST", "https://evil.test/", strings.NewReader("hello"))
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a:b")))
	used, err := in.RewriteRequest(r, "evil.test", true)
	if err != nil || len(used) != 0 {
		t.Fatalf("used=%v err=%v", used, err)
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != "hello" {
		t.Fatalf("body = %q", body)
	}
}

func TestScrub(t *testing.T) {
	in := testInjector(t)
	src := "token is " + ghVal + " and key is " + aiVal + "."
	got, err := io.ReadAll(in.ScrubReader(iotest.OneByteReader(strings.NewReader(src))))
	if err != nil {
		t.Fatal(err)
	}
	want := "token is " + ghPH + " and key is " + aiPH + "."
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	h := http.Header{"Echo": {"Bearer " + ghVal}}
	in.ScrubHeaders(h)
	if h.Get("Echo") != "Bearer "+ghPH {
		t.Fatalf("header = %q", h.Get("Echo"))
	}
}

func TestNilInjector(t *testing.T) {
	var in *Injector
	r := httptest.NewRequest("GET", "https://x.test/", nil)
	if _, err := in.RewriteRequest(r, "x.test", true); err != nil || in.Intercepts("x.test") || in.HasScrub() {
		t.Fatal("nil injector must be a no-op")
	}
}

package probe

import (
	"strings"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	scheme, params := parseChallenge(`Digest realm="router", nonce="abc123", qop="auth", opaque="xyz"`)
	if scheme != "digest" {
		t.Fatalf("scheme = %q", scheme)
	}
	if params["realm"] != "router" || params["nonce"] != "abc123" || params["qop"] != "auth" || params["opaque"] != "xyz" {
		t.Fatalf("params = %#v", params)
	}

	scheme, params = parseChallenge(`Basic realm="unused"`)
	if scheme != "basic" || params["realm"] != "unused" {
		t.Fatalf("basic challenge = %q %#v", scheme, params)
	}
}

func TestDigestAuthorization(t *testing.T) {
	_, params := parseChallenge(`Digest realm="test", nonce="abc", opaque="op"`)
	header, ok := digestAuthorization(params, "GET", "/", "admin", "admin")
	if !ok {
		t.Fatal("digestAuthorization failed")
	}
	ha1 := md5hex("admin:test:admin")
	ha2 := md5hex("GET:/")
	want := md5hex(ha1 + ":abc:" + ha2)
	if !strings.Contains(header, `response="`+want+`"`) {
		t.Fatalf("header %q does not contain %q", header, want)
	}
	if !strings.Contains(header, `opaque="op"`) {
		t.Fatalf("opaque missing: %q", header)
	}
}

func TestIACFilter(t *testing.T) {
	f := &iacFilter{}
	// IAC WILL ECHO followed by text.
	clean, replies := f.Feed([]byte{255, 251, 1, 'l', 'o', 'g', 'i', 'n', ':', ' '})
	if string(clean) != "login: " {
		t.Fatalf("clean = %q", clean)
	}
	if len(replies) != 3 || replies[0] != 255 || replies[1] != 252 || replies[2] != 1 {
		t.Fatalf("replies = %v", replies)
	}

	// Split sequence across reads.
	f = &iacFilter{}
	clean, _ = f.Feed([]byte{255})
	if len(clean) != 0 {
		t.Fatalf("unexpected clean %q", clean)
	}
	clean, _ = f.Feed([]byte{251, 1, 'x'})
	if string(clean) != "x" {
		t.Fatalf("clean = %q", clean)
	}
}

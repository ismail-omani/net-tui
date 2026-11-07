package probe

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
)

// parseChallenge parses an HTTP/RTSP authentication challenge such as
// `Digest realm="x", nonce="y", qop="auth"`.
func parseChallenge(header string) (string, map[string]string) {
	header = strings.TrimSpace(header)
	params := map[string]string{}
	i := strings.IndexByte(header, ' ')
	if i < 0 {
		return strings.ToLower(header), params
	}
	scheme := strings.ToLower(strings.TrimSpace(header[:i]))
	rest := header[i+1:]

	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " ,\t")
		if rest == "" {
			break
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = rest[eq+1:]

		var val string
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			var b strings.Builder
			escaped := false
			idx := 0
			for ; idx < len(rest); idx++ {
				c := rest[idx]
				if escaped {
					b.WriteByte(c)
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					idx++
					break
				}
				b.WriteByte(c)
			}
			val = b.String()
			if idx < len(rest) {
				rest = rest[idx:]
			} else {
				rest = ""
			}
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				val = strings.TrimSpace(rest)
				rest = ""
			} else {
				val = strings.TrimSpace(rest[:end])
				rest = rest[end:]
			}
		}
		params[key] = val
	}
	return scheme, params
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func digestHash(algorithm string) func(string) string {
	a := strings.ToLower(strings.TrimSpace(algorithm))
	a = strings.TrimSuffix(a, "-sess")
	switch a {
	case "sha-256":
		return func(s string) string {
			sum := sha256.Sum256([]byte(s))
			return hex.EncodeToString(sum[:])
		}
	case "sha-512-256":
		return func(s string) string {
			sum := sha512.Sum512_256([]byte(s))
			return hex.EncodeToString(sum[:])
		}
	default:
		return md5hex
	}
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "0123456789abcdef"
	}
	return hex.EncodeToString(buf)
}

// digestAuthorization builds a Digest Authorization header value. The second
// return value is false when the challenge is unusable.
func digestAuthorization(params map[string]string, method, uri, user, pass string) (string, bool) {
	realm := params["realm"]
	nonce := params["nonce"]
	if nonce == "" {
		return "", false
	}

	algorithm := strings.ToLower(params["algorithm"])
	hash := digestHash(algorithm)
	ha1 := hash(user + ":" + realm + ":" + pass)
	ha2 := hash(method + ":" + uri)

	qop := strings.TrimSpace(params["qop"])
	var cnonce, nc, qopValue string
	if qop != "" {
		qopValue = "auth"
		if !strings.Contains(strings.ToLower(qop), "auth") {
			qopValue = strings.TrimSpace(strings.Split(qop, ",")[0])
		}
		nc = "00000001"
	}
	if strings.Contains(algorithm, "sess") {
		cnonce = randomHex(8)
		ha1 = hash(ha1 + ":" + nonce + ":" + cnonce)
	}

	var b strings.Builder
	if qopValue != "" {
		if cnonce == "" {
			cnonce = randomHex(8)
		}
		response := hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qopValue + ":" + ha2)
		fmt.Fprintf(&b, `Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%s, cnonce="%s"`,
			user, realm, nonce, uri, response, qopValue, nc, cnonce)
	} else {
		response := hash(ha1 + ":" + nonce + ":" + ha2)
		fmt.Fprintf(&b, `Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
			user, realm, nonce, uri, response)
	}
	if alg := params["algorithm"]; alg != "" {
		fmt.Fprintf(&b, `, algorithm=%s`, alg)
	}
	if opaque := params["opaque"]; opaque != "" {
		fmt.Fprintf(&b, `, opaque="%s"`, opaque)
	}
	return b.String(), true
}

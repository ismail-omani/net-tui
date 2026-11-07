package probe

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"nettui/internal/model"
)

// VNC checks for unauthenticated access and default VNC passwords.
func VNC(ctx context.Context, env Env) (*model.Finding, error) {
	addr := net.JoinHostPort(env.IP, strconv.Itoa(env.Port))
	timeout := env.timeout()

	ok, hasVNCAuth, err := vncTry(ctx, addr, "", timeout)
	if err != nil {
		return nil, err
	}
	if ok {
		env.attempted("", "", true)
		return env.Finding("", ""), nil
	}
	if !hasVNCAuth {
		return nil, nil
	}

	passwords := env.Store.VNCPasswords(env.VendorTexts, env.MaxCreds)
	for _, password := range passwords {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ok, _, err := vncTry(ctx, addr, password, timeout)
		env.attempted("", password, ok)
		if ok {
			return env.Finding("", password), nil
		}
		if err != nil && ctx.Err() == nil {
			env.logf("vnc: %v", err)
		}
	}
	return nil, nil
}

// vncTry returns (authenticated, serverOffersVNCPasswordAuth, error).
func vncTry(ctx context.Context, addr, password string, timeout time.Duration) (bool, bool, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	version := make([]byte, 12)
	if _, err := io.ReadFull(conn, version); err != nil {
		return false, false, err
	}
	minor := 3
	if len(version) >= 11 {
		minor, _ = strconv.Atoi(string(version[8:11]))
	}
	reply := "RFB 003.003\n"
	switch {
	case minor >= 8:
		reply = "RFB 003.008\n"
	case minor >= 7:
		reply = "RFB 003.007\n"
	}
	if _, err := conn.Write([]byte(reply)); err != nil {
		return false, false, err
	}

	if minor >= 7 {
		var count [1]byte
		if _, err := io.ReadFull(conn, count[:]); err != nil {
			return false, false, err
		}
		types := make([]byte, int(count[0]))
		if _, err := io.ReadFull(conn, types); err != nil {
			return false, false, err
		}
		hasNone, hasVNC := false, false
		for _, t := range types {
			switch t {
			case 1:
				hasNone = true
			case 2:
				hasVNC = true
			}
		}
		if hasNone {
			if _, err := conn.Write([]byte{1}); err != nil {
				return false, hasVNC, err
			}
			if minor >= 8 {
				readSecurityResult(conn, 800*time.Millisecond, true)
			}
			return true, hasVNC, nil
		}
		if !hasVNC {
			return false, false, nil
		}
		if _, err := conn.Write([]byte{2}); err != nil {
			return false, true, err
		}
		return vncAuthResponse(conn, password)
	}

	// RFB 3.3: 32-bit security type.
	var secType uint32
	if err := binary.Read(conn, binary.BigEndian, &secType); err != nil {
		return false, false, err
	}
	switch secType {
	case 1:
		return true, false, nil
	case 2:
		return vncAuthResponse(conn, password)
	default:
		return false, false, fmt.Errorf("unsupported VNC security type %d", secType)
	}
}

func vncAuthResponse(conn net.Conn, password string) (bool, bool, error) {
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return false, true, err
	}
	response, err := vncEncrypt(password, challenge)
	if err != nil {
		return false, true, err
	}
	if _, err := conn.Write(response); err != nil {
		return false, true, err
	}
	ok := readSecurityResult(conn, 2*time.Second, false)
	return ok, true, nil
}

// readSecurityResult reads the RFB SecurityResult word. allowMissing is used
// for RFB 3.7 servers that do not send a result for the None security type.
func readSecurityResult(conn net.Conn, timeout time.Duration, allowMissing bool) bool {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var result [4]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		return allowMissing
	}
	return binary.BigEndian.Uint32(result[:]) == 0
}

func vncEncrypt(password string, challenge []byte) ([]byte, error) {
	key := make([]byte, 8)
	copy(key, []byte(password))
	for i := range key {
		key[i] = reverseBits(key[i])
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out, nil
}

func reverseBits(b byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out |= b & 1
		b >>= 1
	}
	return out
}

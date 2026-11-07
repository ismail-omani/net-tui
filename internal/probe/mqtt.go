package probe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"nettui/internal/model"
)

var mqttCounter uint64

// MQTT checks anonymous access and default username/password pairs.
func MQTT(ctx context.Context, env Env) (*model.Finding, error) {
	tlsMode := env.Port == 8883 || env.Protocol == "mqtts"

	ok, err := mqttTry(ctx, env.IP, env.Port, tlsMode, "", "", true, env.timeout())
	env.attempted("", "", ok)
	if ok {
		return env.Finding("", ""), nil
	}
	if err != nil && ctx.Err() == nil {
		env.logf("mqtt anonymous: %v", err)
	}

	for _, c := range env.pairs() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ok, err := mqttTry(ctx, env.IP, env.Port, tlsMode, c.Login, c.Password, false, env.timeout())
		env.attempted(c.Login, c.Password, ok)
		if ok {
			return env.Finding(c.Login, c.Password), nil
		}
		if err != nil && ctx.Err() == nil {
			env.logf("mqtt: %v", err)
		}
	}
	return nil, nil
}

func mqttTry(ctx context.Context, ip string, port int, useTLS bool, login, password string, anonymous bool, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	packet := mqttConnectPacket(login, password, anonymous)
	if _, err := conn.Write(packet); err != nil {
		return false, err
	}

	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false, err
	}
	if header[0]>>4 != 2 {
		return false, fmt.Errorf("unexpected MQTT packet type %d", header[0]>>4)
	}
	remaining, err := readMQTTRemaining(conn)
	if err != nil {
		return false, err
	}
	payload := make([]byte, remaining)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return false, err
	}
	if len(payload) < 2 {
		return false, fmt.Errorf("short CONNACK")
	}
	return payload[1] == 0, nil
}

func readMQTTRemaining(r io.Reader) (int, error) {
	multiplier := 1
	value := 0
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		value += int(b[0]&127) * multiplier
		if b[0]&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, fmt.Errorf("malformed MQTT remaining length")
}

func mqttConnectPacket(login, password string, anonymous bool) []byte {
	clientID := fmt.Sprintf("nettui-%d-%d", time.Now().UnixNano()&0xffff, atomic.AddUint64(&mqttCounter, 1))

	var payload []byte
	payload = appendMQTTString(payload, clientID)

	flags := byte(0x02) // clean session
	if !anonymous {
		flags |= 0x80 | 0x40
		payload = appendMQTTString(payload, login)
		payload = appendMQTTString(payload, password)
	}

	var variable []byte
	variable = appendMQTTString(variable, "MQTT")
	variable = append(variable, 4) // protocol level 3.1.1
	variable = append(variable, flags)
	variable = append(variable, 0, 30) // keepalive
	variable = append(variable, payload...)

	packet := []byte{0x10}
	packet = append(packet, encodeMQTTRemaining(len(variable))...)
	packet = append(packet, variable...)
	return packet
}

func appendMQTTString(dst []byte, s string) []byte {
	if len(s) > 65535 {
		s = s[:65535]
	}
	dst = append(dst, byte(len(s)>>8), byte(len(s)))
	return append(dst, s...)
}

func encodeMQTTRemaining(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 128
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

var _ = binary.BigEndian

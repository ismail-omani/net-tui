package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"nettui/internal/model"
)

// IPP checks Basic authentication on printers (Get-Printer-Attributes).
func IPP(ctx context.Context, env Env) (*model.Finding, error) {
	scheme := "http"
	if env.Protocol == "https" || env.Port == 631 && env.Protocol == "https" {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, env.IP, env.Port)

	status, err := ippRequest(ctx, base, "", "", env.timeout())
	if err != nil {
		return nil, err
	}
	if status == 0x0000 {
		env.logf("ipp: anonymous Get-Printer-Attributes allowed (not recorded)")
		return nil, nil
	}
	if status != 0x0401 && status != 0x0402 {
		return nil, nil
	}

	for _, c := range env.pairs() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		status, err := ippRequest(ctx, base, c.Login, c.Password, env.timeout())
		ok := status == 0x0000
		env.attempted(c.Login, c.Password, ok)
		if ok {
			return env.Finding(c.Login, c.Password), nil
		}
		if err != nil && ctx.Err() == nil {
			env.logf("ipp: %v", err)
		}
	}
	return nil, nil
}

func ippRequest(ctx context.Context, base, login, password string, timeout time.Duration) (uint16, error) {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		DisableKeepAlives: true,
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	defer transport.CloseIdleConnections()

	paths := []string{"/ipp/print", "/", "/printers"}
	var lastErr error
	for _, path := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(ippGetPrinterAttributes(base+path)))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/ipp")
		req.Header.Set("User-Agent", "net-tui")
		if login != "" || password != "" {
			req.SetBasicAuth(login, password)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return 0x0401, nil
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if len(body) >= 4 {
			return binary.BigEndian.Uint16(body[2:4]), nil
		}
		return 0, fmt.Errorf("short IPP response (HTTP %d)", resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no IPP endpoint responded")
	}
	return 0, lastErr
}

func ippGetPrinterAttributes(uri string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x01})             // IPP/1.1
	buf.Write([]byte{0x00, 0x0b})             // Get-Printer-Attributes
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01}) // request id
	buf.WriteByte(0x01)                       // operation attributes tag

	writeAttr := func(tag byte, name, value string) {
		buf.WriteByte(tag)
		buf.Write([]byte{0x00, byte(len(name))})
		buf.WriteString(name)
		buf.Write([]byte{byte(len(value) >> 8), byte(len(value))})
		buf.WriteString(value)
	}
	writeAttr(0x47, "attributes-charset", "utf-8")
	writeAttr(0x48, "attributes-natural-language", "en")
	writeAttr(0x45, "printer-uri", uri)
	writeAttr(0x44, "requested-attributes", "printer-name")
	buf.WriteByte(0x03) // end of attributes
	return buf.Bytes()
}

var _ = strconv.Itoa

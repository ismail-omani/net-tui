package probe

import (
	"context"
	"time"

	"github.com/gosnmp/gosnmp"

	"nettui/internal/model"
)

// SNMP checks default community strings (public/private).
func SNMP(ctx context.Context, env Env) (*model.Finding, error) {
	communities := env.Store.Communities(env.VendorTexts)
	timeout := env.timeout()
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}

	for _, community := range communities {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ok := snmpTry(env.IP, community, timeout)
		env.attempted("", community, ok)
		if ok {
			return env.Finding("", community), nil
		}
	}
	return nil, nil
}

func snmpTry(ip, community string, timeout time.Duration) bool {
	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	if err := params.Connect(); err != nil {
		return false
	}
	defer params.Conn.Close()

	pkt, err := params.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil || pkt == nil || pkt.Error != gosnmp.NoError || len(pkt.Variables) == 0 {
		return false
	}
	switch pkt.Variables[0].Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return false
	}
	return true
}

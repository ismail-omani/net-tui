package scan

import "testing"

const sampleXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="TP-Link"/>
    <hostnames><hostname name="router.lan"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="TP-LINK Router" version="1.0" tunnel="ssl"/>
        <script id="http-title" output="TP-LINK Wireless Router"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="Dropbear sshd"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
      </port>
    </ports>
    <os><osmatch name="Linux 3.2 - 4.9" accuracy="95"/></os>
  </host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	hosts, err := parseNmapXML([]byte(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts", len(hosts))
	}
	h := hosts[0]
	if h.IP != "192.168.1.1" || h.MAC != "aa:bb:cc:dd:ee:ff" || h.MACVendor != "TP-Link" {
		t.Fatalf("host = %+v", h)
	}
	if h.Hostname != "router.lan" {
		t.Fatalf("hostname = %q", h.Hostname)
	}
	if len(h.Ports) != 2 {
		t.Fatalf("got %d ports: %+v", len(h.Ports), h.Ports)
	}
	if h.Ports[0].Title != "TP-LINK Wireless Router" {
		t.Fatalf("title = %q", h.Ports[0].Title)
	}
	if h.Ports[0].Tunnel != "ssl" {
		t.Fatalf("tunnel = %q", h.Ports[0].Tunnel)
	}
	if h.OS == "" {
		t.Fatal("OS not parsed")
	}
}

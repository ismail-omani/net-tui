package scan

import "testing"

func TestParseARPScan(t *testing.T) {
	out := "192.168.1.1\taa:bb:cc:dd:ee:ff\tTP-LINK TECHNOLOGIES CO.,LTD.\n" +
		"192.168.1.2\t11:22:33:44:55:66\tHikvision (DUP: 2)\n" +
		"192.168.1.3\tde:ad:be:ef:00:11\t\n" +
		"not a host line\n"
	entries := parseARPScan(out)
	if len(entries) != 3 {
		t.Fatalf("got %d entries: %+v", len(entries), entries)
	}
	if entries[0].Vendor != "TP-LINK TECHNOLOGIES CO.,LTD." {
		t.Fatalf("vendor = %q", entries[0].Vendor)
	}
	if entries[1].Vendor != "Hikvision" {
		t.Fatalf("DUP suffix not stripped: %q", entries[1].Vendor)
	}
	if entries[2].MAC != "de:ad:be:ef:00:11" {
		t.Fatalf("mac = %q", entries[2].MAC)
	}
}

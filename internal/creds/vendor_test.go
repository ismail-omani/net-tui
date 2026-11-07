package creds

import "testing"

func TestDetectVendors(t *testing.T) {
	cases := map[string]string{
		"TP-LINK TECHNOLOGIES CO.,LTD.":                  "tp-link",
		"Hangzhou Hikvision Digital Technology Co.,Ltd.": "hikvision",
		"Zhejiang Dahua Technology Co.,Ltd.":             "dahua",
		"Routerboard.com":                                "mikrotik",
		"D-Link International":                           "d-link",
		"Ubiquiti Networks":                              "ubiquiti",
		"Shenzhen Reolink Technology Co., Ltd.":          "reolink",
		"Samsung Techwin":                                "hanwha",
		"Western Digital Technologies, Inc.":             "western-digital",
		"HP Inc.":                                        "hp",
		"OpenWrt uHTTPd":                                 "openwrt",
		"DD-WRT (web)":                                   "dd-wrt",
		"OpenWrt uHTTPd Welcome to AmpliFi":              "ubiquiti",
	}
	for input, want := range cases {
		got := DetectVendors(input)
		if len(got) == 0 || got[0] != want {
			t.Errorf("DetectVendors(%q) = %v, want first %q", input, got, want)
		}
	}
}

func TestVendorLabelUnknownFallback(t *testing.T) {
	got := VendorLabel("(Unknown: locally administered)", "OpenWrt uHTTPd", "Welcome to AmpliFi")
	if got != "Ubiquiti" {
		t.Fatalf("VendorLabel = %q, want Ubiquiti", got)
	}

	if got := VendorLabel("(Unknown: locally administered)"); got != "" {
		t.Fatalf("unknown vendor without hints = %q, want empty", got)
	}

	if got := VendorLabel("TP-LINK TECHNOLOGIES CO.,LTD."); got != "TP-Link" {
		t.Fatalf("known OUI vendor = %q, want TP-Link", got)
	}
}

func TestDisplayVendor(t *testing.T) {
	if got := DisplayVendor("tp-link"); got != "TP-Link" {
		t.Fatalf("DisplayVendor = %q", got)
	}
	if got := DisplayVendor("mikrotik"); got != "MikroTik" {
		t.Fatalf("DisplayVendor = %q", got)
	}
}

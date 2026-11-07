package creds

import (
	"sort"
	"strings"
	"unicode"
)

// brandAliases maps a canonical vendor key to strings commonly found in
// arp-scan OUI vendors, nmap product names and HTTP titles.
var brandAliases = map[string][]string{
	"2wire":           {"2wire"},
	"3com":            {"3com"},
	"actiontec":       {"actiontec"},
	"airlive":         {"airlive"},
	"amcrest":         {"amcrest"},
	"apple":           {"apple"},
	"arris":           {"arris"},
	"asus":            {"asus", "asustek"},
	"avtech":          {"avtech"},
	"axis":            {"axis"},
	"belkin":          {"belkin"},
	"bosch":           {"bosch"},
	"brother":         {"brother"},
	"buffalo":         {"buffalo"},
	"canon":           {"canon"},
	"cisco":           {"cisco"},
	"d-link":          {"d-link", "dlink", "d link"},
	"dahua":           {"dahua"},
	"dell":            {"dell"},
	"edimax":          {"edimax"},
	"epson":           {"epson"},
	"foscam":          {"foscam"},
	"gigabyte":        {"gigabyte"},
	"grandstream":     {"grandstream"},
	"hanwha":          {"hanwha", "samsung techwin"},
	"hikvision":       {"hikvision"},
	"hp":              {"hewlett packard", "hp inc", "hewlett-packard", "hp"},
	"huawei":          {"huawei"},
	"intel":           {"intel"},
	"juniper":         {"juniper"},
	"kyocera":         {"kyocera"},
	"lexmark":         {"lexmark"},
	"linksys":         {"linksys"},
	"mikrotik":        {"mikrotik", "routeros", "routerboard"},
	"motorola":        {"motorola"},
	"netgear":         {"netgear"},
	"nokia":           {"nokia"},
	"panasonic":       {"panasonic"},
	"polycom":         {"polycom"},
	"qnap":            {"qnap"},
	"raspberry":       {"raspberry pi", "raspberry"},
	"realtek":         {"realtek"},
	"reolink":         {"reolink"},
	"ricoh":           {"ricoh"},
	"samsung":         {"samsung"},
	"sharp":           {"sharp"},
	"shelly":          {"shelly"},
	"sonoff":          {"sonoff", "itead"},
	"sony":            {"sony"},
	"synology":        {"synology"},
	"tenda":           {"tenda"},
	"toshiba":         {"toshiba"},
	"tp-link":         {"tp-link", "tplink", "tp link"},
	"tuya":            {"tuya"},
	"ubiquiti":        {"ubiquiti", "ubnt", "amplifi", "unifi"},
	"vivotek":         {"vivotek"},
	"western-digital": {"western digital", "wdc"},
	"xiaomi":          {"xiaomi"},
	"xerox":           {"xerox"},
	"yealink":         {"yealink"},
	"zte":             {"zte"},
	"zyxel":           {"zyxel"},
	"amazon":          {"amazon"},
	"arcadyan":        {"arcadyan"},
	"askey":           {"askey"},
	"avm":             {"avm", "fritz"},
	"calix":           {"calix"},
	"espressif":       {"espressif"},
	"fiberhome":       {"fiberhome"},
	"geovision":       {"geovision"},
	"google":          {"google"},
	"hitron":          {"hitron"},
	"intelbras":       {"intelbras"},
	"konica":          {"konica", "minolta"},
	"mercusys":        {"mercusys"},
	"mitrastar":       {"mitrastar"},
	"oki":             {"oki"},
	"philips":         {"philips", "signify"},
	"roku":            {"roku"},
	"sagemcom":        {"sagemcom"},
	"sercomm":         {"sercomm"},
	"technicolor":     {"technicolor"},
	"tiandy":          {"tiandy"},
	"totolink":        {"totolink"},
	"trendnet":        {"trendnet"},
	"uniview":         {"uniview"},
	"openwrt":         {"openwrt", "luci"},
	"dd-wrt":          {"dd-wrt", "ddwrt", "dd wrt"},
}

var brandDisplay = map[string]string{
	"2wire":           "2Wire",
	"3com":            "3Com",
	"actiontec":       "Actiontec",
	"airlive":         "AirLive",
	"amcrest":         "Amcrest",
	"apple":           "Apple",
	"arris":           "Arris",
	"asus":            "ASUS",
	"avtech":          "AVTECH",
	"axis":            "Axis",
	"belkin":          "Belkin",
	"bosch":           "Bosch",
	"brother":         "Brother",
	"buffalo":         "Buffalo",
	"canon":           "Canon",
	"cisco":           "Cisco",
	"d-link":          "D-Link",
	"dahua":           "Dahua",
	"dell":            "Dell",
	"edimax":          "Edimax",
	"epson":           "Epson",
	"foscam":          "Foscam",
	"gigabyte":        "Gigabyte",
	"grandstream":     "Grandstream",
	"hanwha":          "Hanwha",
	"hikvision":       "Hikvision",
	"hp":              "HP",
	"huawei":          "Huawei",
	"intel":           "Intel",
	"juniper":         "Juniper",
	"kyocera":         "Kyocera",
	"lexmark":         "Lexmark",
	"linksys":         "Linksys",
	"mikrotik":        "MikroTik",
	"motorola":        "Motorola",
	"netgear":         "Netgear",
	"nokia":           "Nokia",
	"panasonic":       "Panasonic",
	"polycom":         "Polycom",
	"qnap":            "QNAP",
	"raspberry":       "Raspberry Pi",
	"realtek":         "Realtek",
	"reolink":         "Reolink",
	"ricoh":           "Ricoh",
	"samsung":         "Samsung",
	"sharp":           "Sharp",
	"shelly":          "Shelly",
	"sonoff":          "Sonoff",
	"sony":            "Sony",
	"synology":        "Synology",
	"tenda":           "Tenda",
	"toshiba":         "Toshiba",
	"tp-link":         "TP-Link",
	"tuya":            "Tuya",
	"ubiquiti":        "Ubiquiti",
	"vivotek":         "Vivotek",
	"western-digital": "Western Digital",
	"xiaomi":          "Xiaomi",
	"xerox":           "Xerox",
	"yealink":         "Yealink",
	"zte":             "ZTE",
	"zyxel":           "Zyxel",
	"amazon":          "Amazon",
	"arcadyan":        "Arcadyan",
	"askey":           "Askey",
	"avm":             "AVM",
	"calix":           "Calix",
	"espressif":       "Espressif",
	"fiberhome":       "FiberHome",
	"geovision":       "GeoVision",
	"google":          "Google",
	"hitron":          "Hitron",
	"intelbras":       "Intelbras",
	"konica":          "Konica Minolta",
	"mercusys":        "Mercusys",
	"mitrastar":       "MitraStar",
	"oki":             "OKI",
	"philips":         "Philips",
	"roku":            "Roku",
	"sagemcom":        "Sagemcom",
	"sercomm":         "Sercomm",
	"technicolor":     "Technicolor",
	"tiandy":          "Tiandy",
	"totolink":        "TOTOLINK",
	"trendnet":        "TRENDnet",
	"uniview":         "Uniview",
	"openwrt":         "OpenWrt",
	"dd-wrt":          "DD-WRT",
}

// Normalize lowercases text and converts every non-alphanumeric rune to a
// single space.
func Normalize(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
			continue
		}
		if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

// DetectVendors returns canonical brand keys found in the supplied texts,
// most specific match first.
func DetectVendors(texts ...string) []string {
	joined := " " + Normalize(strings.Join(texts, " ")) + " "
	compact := strings.ReplaceAll(joined, " ", "")

	type hit struct {
		brand string
		score int
	}
	var hits []hit
	for brand, aliases := range brandAliases {
		best := 0
		for _, alias := range aliases {
			a := Normalize(alias)
			if a == "" {
				continue
			}
			matched := false
			if strings.Contains(joined, " "+a+" ") {
				matched = true
			} else if len(a) >= 5 && strings.Contains(compact, strings.ReplaceAll(a, " ", "")) {
				matched = true
			}
			if matched && len(a) > best {
				best = len(a)
			}
		}
		if best > 0 {
			hits = append(hits, hit{brand: brand, score: best})
		}
	}
	// Longest alias wins, so "samsung techwin" beats "samsung". Ties are
	// resolved deterministically and hardware brands outrank firmware names
	// such as OpenWrt or DD-WRT.
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		pi, pj := vendorPriority(hits[i].brand), vendorPriority(hits[j].brand)
		if pi != pj {
			return pi > pj
		}
		return hits[i].brand < hits[j].brand
	})
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.brand)
	}
	return out
}

// vendorPriority ranks hardware brands above firmware projects. It keeps a
// router that reports both "AmpliFi" and "OpenWrt uHTTPd" labelled by its
// actual brand.
func vendorPriority(brand string) int {
	switch brand {
	case "openwrt", "dd-wrt":
		return 1
	default:
		return 2
	}
}

// DisplayVendor returns a human-friendly name for a canonical brand key.
func DisplayVendor(brand string) string {
	if d, ok := brandDisplay[brand]; ok {
		return d
	}
	return capitalize(brand)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		r := []rune(p)
		r[0] = unicode.ToUpper(r[0])
		parts[i] = string(r)
	}
	return strings.Join(parts, "-")
}

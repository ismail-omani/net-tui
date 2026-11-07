// Package model contains the shared data types used by discovery, probing,
// reporting and the TUI.
package model

import "time"

// Phase describes the current stage of a network scan.
type Phase int

const (
	PhaseIdle Phase = iota
	PhaseDiscover
	PhasePortScan
	PhaseProbe
	PhaseDone
)

func (p Phase) String() string {
	switch p {
	case PhaseDiscover:
		return "Discovering hosts"
	case PhasePortScan:
		return "Scanning ports"
	case PhaseProbe:
		return "Trying credentials"
	case PhaseDone:
		return "Done"
	default:
		return "Idle"
	}
}

// Port is a single open TCP port discovered by nmap.
type Port struct {
	Number   int    `json:"port"`
	Protocol string `json:"proto"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Tunnel   string `json:"tunnel,omitempty"`
	Title    string `json:"title,omitempty"`
}

// Finding is a successful login with default credentials.
type Finding struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Vendor   string `json:"vendor"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Device is one host found on the local network.
type Device struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	Ports    []Port    `json:"ports,omitempty"`
	Status   string    `json:"status"`
	Findings []Finding `json:"findings,omitempty"`
	Notes    []string  `json:"notes,omitempty"`
}

// EventType identifies what changed inside the engine.
type EventType int

const (
	EvLog EventType = iota
	EvPhase
	EvProgress
	EvDevices
	EvFinding
	EvDone
	EvError
)

// Event is sent from the engine to the UI (or the headless printer).
type Event struct {
	Type     EventType
	Time     time.Time
	Phase    Phase
	Message  string
	Level    string // info, warn, error, success, debug
	Progress float64
	Devices  []Device
	IP       string
	Finding  *Finding
	Err      error
}

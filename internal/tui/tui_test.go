package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"nettui/internal/model"
)

func TestEngineDoneSchedulesAutoQuit(t *testing.T) {
	m := New(Config{ResultsDir: "results"})
	m.gen = 1
	m.done = true
	m.scanning = true

	updated, cmd := m.Update(engineDoneMsg{gen: 1})
	got, ok := updated.(Model)
	if !ok {
		t.Fatal("unexpected model type")
	}
	if !got.closing {
		t.Fatal("closing flag was not set")
	}
	if cmd == nil {
		t.Fatal("expected a delayed quit command")
	}

	updated, cmd = got.Update(autoQuitMsg{gen: 1})
	if cmd == nil {
		t.Fatal("expected tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("auto quit did not return tea.QuitMsg")
	}
	_ = updated
}

func TestStaleAutoQuitIsIgnored(t *testing.T) {
	m := New(Config{ResultsDir: "results"})
	m.gen = 2
	m.done = true

	_, cmd := m.Update(autoQuitMsg{gen: 1})
	if cmd != nil {
		t.Fatal("stale auto-quit must be ignored after rescan")
	}
}

func TestRenderTableFitsWidth(t *testing.T) {
	m := New(Config{})
	m.width = 80
	m.height = 24
	m.devices = []model.Device{{
		IP:     "192.168.198.1",
		MAC:    "aa:bb:cc:dd:ee:ff",
		Vendor: "Very Long Vendor Name That Must Be Truncated",
		Ports:  []model.Port{{Number: 80}},
		Status: "probing",
	}}

	out := m.renderTable(80, 24)
	for _, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > 80 {
			t.Fatalf("line width %d > 80: %q", w, line)
		}
	}
}

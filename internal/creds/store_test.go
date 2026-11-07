package creds

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStore(t *testing.T) {
	dir := t.TempDir()
	csv := "Vendor,Username,Password,Comments\n" +
		"Hikvision,admin,12345,\n" +
		"Hikvision,admin,<BLANK>,\n" +
		"Some Unknown Vendor,root,toor,\n"
	if err := os.WriteFile(filepath.Join(dir, seclistsFile), []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	routers := "admin:admin\nroot:\n"
	if err := os.WriteFile(filepath.Join(dir, routersploitFile), []byte(routers), 0o644); err != nil {
		t.Fatal(err)
	}

	store, warnings, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	pairs := store.PairsFor([]string{"Hangzhou Hikvision Digital Technology"}, 10)
	if len(pairs) == 0 {
		t.Fatal("no credentials for hikvision")
	}
	if pairs[0].Login != "admin" || pairs[0].Password != "12345" {
		t.Fatalf("vendor credential should come first, got %+v", pairs[0])
	}

	foundBlank := false
	for _, p := range pairs {
		if p.Login == "admin" && p.Password == "" {
			foundBlank = true
		}
	}
	if !foundBlank {
		t.Fatal("<BLANK> was not normalized to an empty password")
	}

	generic := store.PairsFor([]string{"Unknown Brand"}, 10)
	if len(generic) == 0 || generic[0].Login != "admin" || generic[0].Password != "admin" {
		t.Fatalf("generic list should start with admin/admin, got %+v", generic[0])
	}
}

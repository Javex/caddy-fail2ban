package caddy_fail2ban

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func setupTest(t *testing.T) (string, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "caddy-fail2ban-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}

	fail2banFile := path.Join(tempDir, "banned-ips")
	return tempDir, fail2banFile
}

func cleanupTest(t *testing.T, tempDir string) {
	t.Helper()
	err := os.RemoveAll(tempDir)
	if err != nil {
		t.Fatalf("error removing temp directory: %v", err)
	}
}

func TestModule(t *testing.T) {
	tempDir, fail2banFile := setupTest(t)
	defer cleanupTest(t, tempDir)

	d := caddyfile.NewTestDispenser(fmt.Sprintf(`fail2ban %s`, fail2banFile))

	m := Fail2Ban{}
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unmarshal error: %v", err)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = m.Provision(ctx)
	if err != nil {
		t.Errorf("error provisioning: %v", err)
	}
	defer func() {
		err := m.Cleanup()
		if err != nil {
			t.Fatalf("unexpected error on cleanup: %v", err)
		}
	}()

	req := httptest.NewRequest("GET", "https://127.0.0.1", strings.NewReader(""))

	if got, exp := m.Match(req), false; got != exp {
		t.Errorf("unexpected match. got: %t, exp: %t", got, exp)
	}

	bannedIps, err := m.banlist.getBannedIps()
	if err != nil {
		t.Errorf("error loading banned ips: %v", err)
	}

	if got, exp := len(bannedIps), 0; got != exp {
		t.Errorf("unexpected number of banned IPs. got: %d, exp: %d", got, exp)
	}
}

func TestHeaderBan(t *testing.T) {
	tempDir, fail2banFile := setupTest(t)
	defer cleanupTest(t, tempDir)

	d := caddyfile.NewTestDispenser(fmt.Sprintf(`fail2ban %s`, fail2banFile))

	m := Fail2Ban{}
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unmarshal error: %v", err)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = m.Provision(ctx)
	if err != nil {
		t.Errorf("error provisioning: %v", err)
	}
	defer func() {
		err := m.Cleanup()
		if err != nil {
			t.Fatalf("unexpected error on cleanup: %v", err)
		}
	}()

	req := httptest.NewRequest("GET", "https://127.0.0.1", strings.NewReader(""))
	req.Header.Add("X-Caddy-Ban", "1")

	if got, exp := m.Match(req), true; got != exp {
		t.Errorf("unexpected match. got: %t, exp: %t", got, exp)
	}
}

func TestBanIp(t *testing.T) {
	tempDir, fail2banFile := setupTest(t)
	defer cleanupTest(t, tempDir)

	d := caddyfile.NewTestDispenser(fmt.Sprintf(`fail2ban %s`, fail2banFile))

	m := Fail2Ban{}
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unmarshal error: %v", err)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = m.Provision(ctx)
	if err != nil {
		t.Errorf("error provisioning: %v", err)
	}
	defer func() {
		err := m.Cleanup()
		if err != nil {
			t.Fatalf("unexpected error on cleanup: %v", err)
		}
	}()

	req := httptest.NewRequest("GET", "https://127.0.0.1", strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:1337"

	if m.Match(req) {
		t.Errorf("IP banned unexpectedly")
	}

	// ban IP
	reloadEvent := make(chan bool)
	m.banlist.subscribeToReload(reloadEvent)
	os.WriteFile(fail2banFile, []byte("127.0.0.1"), 0644)
	<-reloadEvent

	req = httptest.NewRequest("GET", "https://127.0.0.1", strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:1337"

	if !m.Match(req) {
		t.Errorf("IP should have been banned")
	}
}

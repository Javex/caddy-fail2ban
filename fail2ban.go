package caddy_fail2ban

import (
	"fmt"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Fail2Ban{})
}

// Fail2Ban implements an HTTP handler that checks a specified file for banned
// IPs and matches if they are found
type Fail2Ban struct {
	Banfile string `json:"banfile"`

	logger  *zap.Logger
	banlist Banlist
}

// CaddyModule returns the Caddy module information.
func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.fail2ban",
		New: func() caddy.Module { return new(Fail2Ban) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Fail2Ban) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.banlist = NewBanlist(m.logger, &m.Banfile)
	m.banlist.Start()
	return nil
}

func (m *Fail2Ban) Cleanup() error {
	return m.banlist.Stop()
}

// Validate implements caddy.Validator.
// func (m *Fail2Ban) Validate() error {
// 	// if m.w == nil {
// 	// 	return fmt.Errorf("no writer")
// 	// }
// 	return nil
// }

func (m *Fail2Ban) Match(req *http.Request) bool {
	remote_ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		m.logger.Error("Error parsing remote addr into IP & port", zap.String("remote_addr", req.RemoteAddr), zap.Error(err))
		// Deny by default
		return true
	}

	// Only ban if header X-Caddy-Ban is sent
	_, ok := req.Header["X-Caddy-Ban"]
	if ok {
		m.logger.Info("banned IP", zap.String("remote_addr", remote_ip))
		return true
	}

	if m.banlist.IsBanned(remote_ip) == true {
		m.logger.Info("banned IP", zap.String("remote_addr", remote_ip))
		return true
	}

	m.logger.Debug("received request", zap.String("remote_addr", remote_ip))
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Fail2Ban) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		switch v := d.Val(); v {
		case "fail2ban":
			if !d.Next() {
				return fmt.Errorf("fail2ban expects file path, value is missing")
			}
			m.Banfile = d.Val()
		default:
			return fmt.Errorf("unknown config value: %s", v)

		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
// func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
// 	var m Fail2Ban
// 	err := m.UnmarshalCaddyfile(h.Dispenser)
// 	return m, err
// }

// Interface guards
var (
	_ caddy.Provisioner  = (*Fail2Ban)(nil)
	_ caddy.CleanerUpper = (*Fail2Ban)(nil)
	// _ caddy.Validator          = (*Fail2Ban)(nil)
	_ caddyhttp.RequestMatcher = (*Fail2Ban)(nil)
	_ caddyfile.Unmarshaler    = (*Fail2Ban)(nil)
)

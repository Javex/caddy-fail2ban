package caddy_fail2ban

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	// httpcaddyfile.RegisterHandlerDirective("visitor_ip", parseCaddyfile)
}

// Middleware implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type Middleware struct {
	// The file or stream to write to. Can be "stdout"
	// or "stderr".
	Output string `json:"output,omitempty"`

	// w io.Writer

	Banfile string `json:"banfile"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.fail2ban",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

func (m *Middleware) getBannedIps() ([]string, error) {

	// Open banfile
	// Try to open file
	banfileHandle, err := os.Open(m.Banfile)
	if err != nil {
		m.logger.Info("Creating new file at since Open failed", zap.String("banfile", m.Banfile), zap.Error(err))
		// Try to create new file, maybe the file didn't exist yet
		banfileHandle, err = os.Create(m.Banfile)
		if err != nil {
			m.logger.Error("Error creating banfile", zap.String("banfile", m.Banfile), zap.Error(err))
			return nil, fmt.Errorf("cannot open or create banfile: %v", err)
		}
	}
	defer banfileHandle.Close()

	// read banned IPs
	bannedIps := make([]string, 0)
	scanner := bufio.NewScanner(banfileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		m.logger.Debug("Adding banned IP to list", zap.String("banned_addr", line))
		bannedIps = append(bannedIps, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing banfile: %v", err)
	}

	return bannedIps, nil
}

// Validate implements caddy.Validator.
// func (m *Middleware) Validate() error {
// 	// if m.w == nil {
// 	// 	return fmt.Errorf("no writer")
// 	// }
// 	return nil
// }

func (m *Middleware) Match(req *http.Request) bool {
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

	// check IPs, too
	bannedIps, err := m.getBannedIps()
	if err != nil {
		m.logger.Error("error getting banned IPs", zap.Error(err))
		// Deny by default
		return true
	}

	for _, ip := range bannedIps {
		if ip == remote_ip {
			m.logger.Debug("banned IP", zap.String("remote_addr", remote_ip))
			return true
		}
	}

	m.logger.Debug("received request", zap.String("remote_addr", remote_ip))
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
// 	var m Middleware
// 	err := m.UnmarshalCaddyfile(h.Dispenser)
// 	return m, err
// }

// Interface guards
var (
	_ caddy.Provisioner = (*Middleware)(nil)
	// _ caddy.Validator          = (*Middleware)(nil)
	_ caddyhttp.RequestMatcher = (*Middleware)(nil)
	_ caddyfile.Unmarshaler    = (*Middleware)(nil)
)

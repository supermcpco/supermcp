// Package ssrf keeps outbound connections away from private networks.
//
// The check lives in the dialer, not in a pre-flight: the hostname is
// resolved once, every address is classified, and the connection is made to
// one of the addresses that passed. A DNS answer that changes between check
// and connect (rebinding) therefore cannot reach a blocked address.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Policy decides which destinations are allowed.
type Policy struct {
	// Disabled turns the guard off entirely. Never in production.
	Disabled bool
	// AllowLoopback permits 127.0.0.0/8 and ::1 (dev, e2e).
	AllowLoopback bool
	// AllowPrivate permits RFC 1918 ranges, CGNAT and ULA. Prefer AllowedHosts.
	AllowPrivate bool
	// AllowedHosts are exact hostnames or "*.suffix" patterns that bypass
	// address classification (for on-prem systems on private IPs).
	AllowedHosts []string

	mu    sync.RWMutex
	extra func() []string // dynamic allowlist (site settings), may be nil
}

// ErrBlocked is wrapped by every refusal.
var ErrBlocked = errors.New("destination blocked by SSRF policy")

// SetDynamicAllowlist installs a provider for operator-managed allowed
// hosts, consulted on every check.
func (p *Policy) SetDynamicAllowlist(fn func() []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.extra = fn
}

// HostAllowed reports whether host matches the static or dynamic allowlist.
func (p *Policy) HostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if matchAny(host, p.AllowedHosts) {
		return true
	}
	p.mu.RLock()
	fn := p.extra
	p.mu.RUnlock()
	if fn != nil && matchAny(host, fn()) {
		return true
	}
	return false
}

func matchAny(host string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		switch {
		case pat == "":
		case strings.HasPrefix(pat, "*."):
			if host == pat[2:] || strings.HasSuffix(host, pat[1:]) {
				return true
			}
		case pat == host:
			return true
		}
	}
	return false
}

// Classification of an address.
type Class int

const (
	Public Class = iota
	Loopback
	Private   // RFC 1918, CGNAT, ULA
	LinkLocal // 169.254/16 incl. cloud metadata, fe80::/10
	Special   // unspecified, multicast, reserved, broadcast, documentation
)

var (
	v4Private = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
	v4Special = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	v6ULA   = netip.MustParsePrefix("fc00::/7")
	v6LL    = netip.MustParsePrefix("fe80::/10")
	v6Doc   = netip.MustParsePrefix("2001:db8::/32")
	v6NAT   = netip.MustParsePrefix("64:ff9b::/96") // NAT64: classify the embedded v4
	v6Mcast = netip.MustParsePrefix("ff00::/8")
)

// Classify puts an address in a class. IPv4-mapped and NAT64 addresses are
// classified by their embedded IPv4 address.
func Classify(a netip.Addr) Class {
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is6() && v6NAT.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	switch {
	case a.IsLoopback():
		return Loopback
	case a.IsUnspecified(), a.IsMulticast(), a.IsInterfaceLocalMulticast():
		return Special
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return LinkLocal
	}
	if a.Is4() {
		for _, p := range v4Private {
			if p.Contains(a) {
				return Private
			}
		}
		for _, p := range v4Special {
			if p.Contains(a) {
				return Special
			}
		}
		if a == netip.MustParseAddr("255.255.255.255") {
			return Special
		}
		return Public
	}
	switch {
	case v6ULA.Contains(a):
		return Private
	case v6LL.Contains(a):
		return LinkLocal
	case v6Doc.Contains(a), v6Mcast.Contains(a):
		return Special
	}
	return Public
}

// AddrAllowed applies the policy to one address.
func (p *Policy) AddrAllowed(a netip.Addr) bool {
	if p.Disabled {
		return true
	}
	switch Classify(a) {
	case Public:
		return true
	case Loopback:
		return p.AllowLoopback
	case Private:
		return p.AllowPrivate
	default:
		return false
	}
}

// Resolver resolves names; the default uses net.DefaultResolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer is a DialContext implementation that enforces the policy.
type Dialer struct {
	Policy   *Policy
	Resolver Resolver
	Base     *net.Dialer
}

// NewDialer returns a dialer with sane defaults.
func NewDialer(p *Policy) *Dialer {
	return &Dialer{Policy: p, Resolver: net.DefaultResolver, Base: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}}
}

// DialContext resolves, checks every address, and connects to the first
// allowed one (in resolver order).
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if d.Policy.Disabled || d.Policy.HostAllowed(host) {
		return d.Base.DialContext(ctx, network, addr)
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if !d.Policy.AddrAllowed(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s (%s)", ErrBlocked, host, ip, className(Classify(ip)))
		}
		return d.Base.DialContext(ctx, network, addr)
	}
	ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	for _, ip := range ips {
		if !d.Policy.AddrAllowed(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s (%s)", ErrBlocked, host, ip, className(Classify(ip)))
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.Base.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// CheckHost resolves and classifies without connecting, for validation at
// configuration time (e.g. a database host). The returned addresses are
// the ones a caller may connect to by IP.
func (d *Dialer) CheckHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if d.Policy.Disabled || d.Policy.HostAllowed(host) {
		return nil, nil
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if !d.Policy.AddrAllowed(ip) {
			return nil, fmt.Errorf("%w: %s (%s)", ErrBlocked, ip, className(Classify(ip)))
		}
		return []netip.Addr{ip}, nil
	}
	ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !d.Policy.AddrAllowed(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s (%s)", ErrBlocked, host, ip, className(Classify(ip)))
		}
	}
	return ips, nil
}

func className(c Class) string {
	switch c {
	case Loopback:
		return "loopback"
	case Private:
		return "private network"
	case LinkLocal:
		return "link-local"
	case Special:
		return "reserved"
	}
	return "public"
}

// FromEnv builds a policy from SUPERMCP_SSRF_* variables.
func FromEnv(get func(string) string) *Policy {
	p := &Policy{
		Disabled:      get("SUPERMCP_SSRF_GUARD") == "disabled",
		AllowLoopback: get("SUPERMCP_SSRF_ALLOW_LOOPBACK") == "true",
		AllowPrivate:  get("SUPERMCP_SSRF_ALLOW_PRIVATE") == "true",
	}
	for _, h := range strings.Split(get("SUPERMCP_SSRF_ALLOWED_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			p.AllowedHosts = append(p.AllowedHosts, h)
		}
	}
	return p
}

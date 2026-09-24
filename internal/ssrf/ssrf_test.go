package ssrf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"8.8.8.8": Public, "1.1.1.1": Public, "2606:4700::1111": Public,
		"127.0.0.1": Loopback, "127.255.255.255": Loopback, "::1": Loopback,
		"10.0.0.1": Private, "172.16.0.1": Private, "172.31.255.255": Private, "172.32.0.1": Public,
		"192.168.1.1": Private, "100.64.0.1": Private, "100.127.255.255": Private, "fd00::1": Private,
		"169.254.169.254": LinkLocal, "169.254.0.1": LinkLocal, "fe80::1": LinkLocal,
		"0.0.0.0": Special, "224.0.0.1": Special, "240.0.0.1": Special, "255.255.255.255": Special,
		"192.0.2.1": Special, "198.18.0.1": Special, "2001:db8::1": Special, "ff02::1": Special, "::": Special,
		"::ffff:169.254.169.254": LinkLocal, "::ffff:10.1.2.3": Private, "::ffff:8.8.8.8": Public,
		"64:ff9b::a9fe:a9fe": LinkLocal, // NAT64-embedded 169.254.169.254
	}
	for in, want := range cases {
		if got := Classify(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s: got %v want %v", in, got, want)
		}
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

func TestDialerBlocksRebinding(t *testing.T) {
	// A hostname whose answer mixes a public and a metadata address is
	// refused outright, never partially connected.
	d := NewDialer(&Policy{})
	d.Resolver = fakeResolver{
		"evil.example": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("169.254.169.254")},
		"meta.example": {netip.MustParseAddr("169.254.169.254")},
		"lan.example":  {netip.MustParseAddr("10.0.0.5")},
	}
	for _, host := range []string{"evil.example:80", "meta.example:80", "lan.example:443", "127.0.0.1:80", "[::1]:80", "10.1.1.1:80"} {
		_, err := d.DialContext(context.Background(), "tcp", host)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: expected ErrBlocked, got %v", host, err)
		}
	}
}

func TestPolicyAllowlist(t *testing.T) {
	p := &Policy{AllowedHosts: []string{"erp.internal", "*.corp.example"}}
	for host, want := range map[string]bool{"erp.internal": true, "ERP.internal.": true, "a.corp.example": true, "corp.example": true, "b.a.corp.example": true, "corp.example.evil": false, "other": false} {
		if got := p.HostAllowed(host); got != want {
			t.Errorf("%s: got %v want %v", host, got, want)
		}
	}
	p.SetDynamicAllowlist(func() []string { return []string{"dyn.example"} })
	if !p.HostAllowed("dyn.example") {
		t.Error("dynamic allowlist not consulted")
	}
	loop := &Policy{AllowLoopback: true}
	if !loop.AddrAllowed(netip.MustParseAddr("127.0.0.1")) {
		t.Error("loopback should be allowed")
	}
	if loop.AddrAllowed(netip.MustParseAddr("169.254.169.254")) {
		t.Error("metadata must never be allowed by AllowLoopback")
	}
	priv := &Policy{AllowPrivate: true}
	if !priv.AddrAllowed(netip.MustParseAddr("10.0.0.1")) || priv.AddrAllowed(netip.MustParseAddr("169.254.1.1")) {
		t.Error("AllowPrivate scope wrong")
	}
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{"SUPERMCP_SSRF_ALLOWED_HOSTS": " a.example, *.b.example ,", "SUPERMCP_SSRF_ALLOW_LOOPBACK": "true"}
	p := FromEnv(func(k string) string { return env[k] })
	if len(p.AllowedHosts) != 2 || !p.AllowLoopback || p.AllowPrivate || p.Disabled {
		t.Errorf("unexpected policy %+v", p)
	}
}

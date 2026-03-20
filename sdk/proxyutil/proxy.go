package proxyutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	transportCache sync.Map // map[string]*http.Transport
	dialerCache    sync.Map // map[string]proxy.Dialer
)

// Mode describes how a proxy setting should be interpreted.
type Mode int

const (
	// ModeInherit means no explicit proxy behavior was configured.
	ModeInherit Mode = iota
	// ModeDirect means outbound requests must bypass proxies explicitly.
	ModeDirect
	// ModeProxy means a concrete proxy URL was configured.
	ModeProxy
	// ModeInvalid means the proxy setting is present but malformed or unsupported.
	ModeInvalid
)

// Setting is the normalized interpretation of a proxy configuration value.
type Setting struct {
	Raw  string
	Mode Mode
	URL  *url.URL
}

// Parse normalizes a proxy configuration value into inherit, direct, or proxy modes.
func Parse(raw string) (Setting, error) {
	trimmed := strings.TrimSpace(raw)
	setting := Setting{Raw: trimmed}

	if trimmed == "" {
		setting.Mode = ModeInherit
		return setting, nil
	}

	if strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		setting.Mode = ModeDirect
		return setting, nil
	}

	parsedURL, errParse := url.Parse(trimmed)
	if errParse != nil {
		setting.Mode = ModeInvalid
		return setting, fmt.Errorf("parse proxy URL failed: %w", errParse)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		setting.Mode = ModeInvalid
		return setting, fmt.Errorf("proxy URL missing scheme/host")
	}

	switch parsedURL.Scheme {
	case "socks5", "http", "https":
		setting.Mode = ModeProxy
		setting.URL = parsedURL
		return setting, nil
	default:
		setting.Mode = ModeInvalid
		return setting, fmt.Errorf("unsupported proxy scheme: %s", parsedURL.Scheme)
	}
}

// tuneTransport applies aggressive connection pooling limits suitable for CLI proxies (e.g. 20+ terminals).
func tuneTransport(t *http.Transport) *http.Transport {
	if t == nil {
		return nil
	}
	t.MaxIdleConns = 1000
	t.MaxIdleConnsPerHost = 100
	t.IdleConnTimeout = 90 * time.Second
	return t
}

// NewDirectTransport returns a transport that bypasses environment proxies.
func NewDirectTransport() *http.Transport {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok && transport != nil {
		clone := transport.Clone()
		clone.Proxy = nil
		return tuneTransport(clone)
	}
	return tuneTransport(&http.Transport{Proxy: nil})
}

// BuildHTTPTransport constructs an HTTP transport for the provided proxy setting.
// It caches transports by raw setting to prevent connection pool exhaustion.
func BuildHTTPTransport(raw string) (*http.Transport, Mode, error) {
	setting, errParse := Parse(raw)
	if errParse != nil {
		return nil, setting.Mode, errParse
	}

	// For inherit mode, do not cache since the transport is nil.
	if setting.Mode == ModeInherit {
		return nil, setting.Mode, nil
	}

	// Check cache
	if cached, ok := transportCache.Load(setting.Raw); ok {
		return cached.(*http.Transport), setting.Mode, nil
	}

	var transport *http.Transport
	switch setting.Mode {
	case ModeDirect:
		transport = NewDirectTransport()
	case ModeProxy:
		// Clone DefaultTransport to inherit TLS config, timeouts, etc.
		if t, ok := http.DefaultTransport.(*http.Transport); ok && t != nil {
			transport = t.Clone()
		} else {
			transport = &http.Transport{}
		}
		transport = tuneTransport(transport)

		if setting.URL.Scheme == "socks5" {
			var proxyAuth *proxy.Auth
			if setting.URL.User != nil {
				username := setting.URL.User.Username()
				password, _ := setting.URL.User.Password()
				proxyAuth = &proxy.Auth{User: username, Password: password}
			}
			dialer, errSOCKS5 := proxy.SOCKS5("tcp", setting.URL.Host, proxyAuth, proxy.Direct)
			if errSOCKS5 != nil {
				return nil, setting.Mode, fmt.Errorf("create SOCKS5 dialer failed: %w", errSOCKS5)
			}
			transport.Proxy = nil
			transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		} else {
			transport.Proxy = http.ProxyURL(setting.URL)
		}
	}

	if transport != nil {
		transportCache.Store(setting.Raw, transport)
	}
	return transport, setting.Mode, nil
}

// BuildDialer constructs a proxy dialer for settings that operate at the connection layer.
// It caches dialers by raw setting.
func BuildDialer(raw string) (proxy.Dialer, Mode, error) {
	setting, errParse := Parse(raw)
	if errParse != nil {
		return nil, setting.Mode, errParse
	}

	if setting.Mode == ModeInherit {
		return nil, setting.Mode, nil
	}

	if cached, ok := dialerCache.Load(setting.Raw); ok {
		return cached.(proxy.Dialer), setting.Mode, nil
	}

	var dialer proxy.Dialer
	switch setting.Mode {
	case ModeDirect:
		dialer = proxy.Direct
	case ModeProxy:
		var errDialer error
		dialer, errDialer = proxy.FromURL(setting.URL, proxy.Direct)
		if errDialer != nil {
			return nil, setting.Mode, fmt.Errorf("create proxy dialer failed: %w", errDialer)
		}
	}

	if dialer != nil {
		dialerCache.Store(setting.Raw, dialer)
	}
	return dialer, setting.Mode, nil
}

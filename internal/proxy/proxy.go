// Package proxy is the per-VM egress proxy. It enforces the VM's network
// policy, tunnels allowed TLS untouched, and opens TLS only to hosts that
// have a secret bound, to swap placeholders for real secrets.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"windevvm/internal/ca"
	"windevvm/internal/hostmatch"
	"windevvm/internal/inject"
	"windevvm/internal/policy"
)

// VM is the configuration the proxy enforces for one VM.
type VM struct {
	Name string
	// SourceIP, if valid, is the only address allowed to use this proxy.
	SourceIP netip.Addr
	Policy   *policy.Policy
	Injector *inject.Injector
}

// Event kinds.
const (
	KindAllow  = "allow"
	KindBlock  = "block"
	KindExfil  = "exfil"
	KindInject = "inject"
	KindError  = "error"
)

// Event is one proxy decision, for logs and `windevvm network log`.
type Event struct {
	Time        time.Time
	VM          string
	Kind        string
	Method      string
	Host        string
	Port        int
	Path        string
	Reason      string
	Rule        string
	Suggest     string
	Secrets     []string
	Intercepted bool
}

// Server is an HTTP proxy for one VM. Run one listener per VM.
type Server struct {
	CA *ca.CA
	// Resolve looks up a hostname. Defaults to the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// UpstreamRoots verifies upstream servers when the proxy opens TLS.
	// Nil means the system roots.
	UpstreamRoots *x509.CertPool
	// OnEvent receives every decision. It must not block.
	OnEvent func(Event)
	// DialTimeout bounds each upstream connection attempt.
	DialTimeout time.Duration

	vm        atomic.Pointer[VM]
	once      sync.Once
	transport *http.Transport
}

// New returns a proxy for vm.
func New(c *ca.CA, vm *VM) *Server {
	s := &Server{CA: c}
	s.vm.Store(vm)
	return s
}

// SetVM swaps in new configuration, e.g. after a policy change.
func (s *Server) SetVM(vm *VM) {
	s.vm.Store(vm)
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}

// Config returns the current configuration.
func (s *Server) Config() *VM { return s.vm.Load() }

func (s *Server) emit(vm *VM, e Event) {
	if s.OnEvent == nil {
		return
	}
	e.Time = time.Now()
	e.VM = vm.Name
	s.OnEvent(e)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vm := s.vm.Load()
	if vm == nil {
		http.Error(w, "windevvm: proxy not configured", http.StatusServiceUnavailable)
		return
	}
	if !sourceOK(vm, r.RemoteAddr) {
		s.emit(vm, Event{Kind: KindBlock, Method: r.Method, Host: r.Host, Reason: "request from unexpected address " + r.RemoteAddr})
		http.Error(w, "windevvm: request from an unexpected address", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r, vm)
	case r.URL.IsAbs():
		s.handlePlain(w, r, vm)
	default:
		http.Error(w, "windevvm: this is a proxy; send proxied requests only", http.StatusBadRequest)
	}
}

func sourceOK(vm *VM, remote string) bool {
	if !vm.SourceIP.IsValid() {
		return true
	}
	ap, err := netip.ParseAddrPort(remote)
	return err == nil && ap.Addr().Unmap() == vm.SourceIP.Unmap()
}

func splitHostPort(hostport string, defPort int) (string, int, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		var ae *net.AddrError
		if errors.As(err, &ae) && ae.Err == "missing port in address" {
			return hostmatch.Normalize(hostport), defPort, nil
		}
		return "", 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port in %q", hostport)
	}
	return hostmatch.Normalize(host), port, nil
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

func writeBlock(w http.ResponseWriter, reason, suggest string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Windevvm-Blocked", "1")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "windevvm blocked this request: %s\n", reason)
	if suggest != "" {
		fmt.Fprintf(w, "To allow it, run on the host: windevvm network allow %s\n", suggest)
	}
}

func (s *Server) block(w http.ResponseWriter, vm *VM, method, host string, port int, d policy.Decision) {
	s.emit(vm, Event{Kind: KindBlock, Method: method, Host: host, Port: port, Reason: d.Reason, Rule: d.Rule, Suggest: d.Suggest})
	writeBlock(w, fmt.Sprintf("%s: %s", hostPort(host, port), d.Reason), d.Suggest)
}

// rejectRequest answers a request that failed placeholder rewriting.
func (s *Server) rejectRequest(w http.ResponseWriter, vm *VM, r *http.Request, host string, port int, err error) {
	kind := KindError
	var v *inject.Violation
	if errors.As(err, &v) {
		kind = KindExfil
	}
	s.emit(vm, Event{Kind: kind, Method: r.Method, Host: host, Port: port, Path: r.URL.Path, Reason: err.Error()})
	writeBlock(w, err.Error(), "")
}

// upstreamError answers a request whose upstream connection failed.
func (s *Server) upstreamError(w http.ResponseWriter, vm *VM, method, host string, port int, err error) {
	var be *BlockedAddrError
	if errors.As(err, &be) {
		s.emit(vm, Event{Kind: KindBlock, Method: method, Host: host, Port: port, Reason: be.Error()})
		writeBlock(w, be.Error(), "")
		return
	}
	s.emit(vm, Event{Kind: KindError, Method: method, Host: host, Port: port, Reason: err.Error()})
	http.Error(w, "windevvm: upstream error: "+err.Error(), http.StatusBadGateway)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request, vm *VM) {
	host, port, err := splitHostPort(r.Host, 443)
	if err != nil {
		http.Error(w, "windevvm: bad CONNECT target", http.StatusBadRequest)
		return
	}
	d := vm.Policy.Decide(host, port)
	if !d.Allow {
		s.block(w, vm, r.Method, host, port, d)
		return
	}
	intercept := vm.Injector.Intercepts(host)

	var upstream net.Conn
	if !intercept {
		if upstream, err = s.dial(r.Context(), vm, hostPort(host, port)); err != nil {
			s.upstreamError(w, vm, r.Method, host, port, err)
			return
		}
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "windevvm: connection can't be hijacked", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	client := &bufConn{Conn: conn, r: brw.Reader}
	s.emit(vm, Event{Kind: KindAllow, Method: r.Method, Host: host, Port: port, Reason: d.Reason, Rule: d.Rule, Intercepted: intercept})

	if intercept {
		s.serveIntercepted(client, vm, host, port)
		return
	}
	tunnel(client, upstream)
}

func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request, vm *VM) {
	if r.URL.Scheme != "http" {
		http.Error(w, "windevvm: only http:// URLs can be proxied directly; use CONNECT for https", http.StatusBadRequest)
		return
	}
	host, port, err := splitHostPort(r.URL.Host, 80)
	if err != nil {
		http.Error(w, "windevvm: bad URL host", http.StatusBadRequest)
		return
	}
	d := vm.Policy.Decide(host, port)
	if !d.Allow {
		s.block(w, vm, r.Method, host, port, d)
		return
	}
	if _, err := vm.Injector.RewriteRequest(r, host, false); err != nil {
		s.rejectRequest(w, vm, r, host, port, err)
		return
	}
	s.emit(vm, Event{Kind: KindAllow, Method: r.Method, Host: host, Port: port, Path: r.URL.Path, Reason: d.Reason, Rule: d.Rule})
	rp := &httputil.ReverseProxy{
		Rewrite:   func(pr *httputil.ProxyRequest) { pr.Out.Host = pr.In.Host },
		Transport: s.getTransport(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.upstreamError(w, vm, r.Method, host, port, err)
		},
		ErrorLog: discardLog,
	}
	rp.ServeHTTP(w, r)
}

var discardLog = log.New(io.Discard, "", 0)

// serveIntercepted terminates the VM's TLS with a leaf from the local CA and
// serves its requests, injecting secrets and forwarding them upstream.
func (s *Server) serveIntercepted(client net.Conn, vm *VM, host string, port int) {
	cert, err := s.CA.Leaf(host)
	if err != nil {
		s.emit(vm, Event{Kind: KindError, Method: http.MethodConnect, Host: host, Port: port, Reason: "leaf certificate: " + err.Error()})
		client.Close()
		return
	}
	tconn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	srv := &http.Server{
		Handler:           s.interceptHandler(vm, host, port),
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          discardLog,
	}
	srv.Serve(newOneConnListener(tconn))
}

func (s *Server) interceptHandler(vm *VM, host string, port int) http.Handler {
	inj := vm.Injector
	target := hostPort(host, port)
	hostHeader := host
	if port != 443 {
		hostHeader = target
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = target
			pr.Out.Host = hostHeader
			// Let the transport negotiate compression and decompress, so
			// response scrubbing sees plain bytes.
			pr.Out.Header.Del("Accept-Encoding")
		},
		Transport:     s.getTransport(),
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			inj.ScrubHeaders(resp.Header)
			if resp.StatusCode != http.StatusSwitchingProtocols && inj.HasScrub() && resp.Body != nil && resp.Body != http.NoBody {
				resp.Body = readCloser{inj.ScrubReader(resp.Body), resp.Body}
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.upstreamError(w, vm, r.Method, host, port, err)
		},
		ErrorLog: discardLog,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		used, err := inj.RewriteRequest(r, host, true)
		if err != nil {
			s.rejectRequest(w, vm, r, host, port, err)
			return
		}
		if len(used) > 0 {
			s.emit(vm, Event{Kind: KindInject, Method: r.Method, Host: host, Port: port, Path: r.URL.Path, Secrets: used, Intercepted: true})
		}
		rp.ServeHTTP(w, r)
	})
}

type readCloser struct {
	io.Reader
	io.Closer
}

func (s *Server) getTransport() *http.Transport {
	s.once.Do(func() {
		s.transport = &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.dial(ctx, s.vm.Load(), addr)
			},
			TLSClientConfig:       &tls.Config{RootCAs: s.UpstreamRoots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	})
	return s.transport
}

// BlockedAddrError means a host resolved only to addresses the policy refuses.
type BlockedAddrError struct {
	Host string
	Err  error
}

func (e *BlockedAddrError) Error() string { return e.Host + ": " + e.Err.Error() }
func (e *BlockedAddrError) Unwrap() error { return e.Err }

// dial resolves addr itself and checks every address against the policy
// before connecting to it, so DNS can't steer a VM onto the host or the LAN.
func (s *Server) dial(ctx context.Context, vm *VM, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = s.resolve(ctx, host); err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	var firstErr error
	for _, ip := range ips {
		ip = ip.Unmap()
		if err := vm.Policy.CheckIP(ip, port); err != nil {
			if firstErr == nil {
				firstErr = &BlockedAddrError{Host: host, Err: err}
			}
			continue
		}
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no addresses found for %s", host)
	}
	return nil, firstErr
}

func (s *Server) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if s.Resolve != nil {
		return s.Resolve(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

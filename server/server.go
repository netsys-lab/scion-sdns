package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	l "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/sdns/server/doh"
)

// Server type
type Server struct {
	addr           string
	tlsAddr        string
	dohAddr        string
	tlsCertificate string
	tlsPrivateKey  string
	scion          bool
	chainPool      sync.Pool
}

// New return new server
func New(cfg *config.Config) *Server {
	if cfg.Bind == "" {
		cfg.Bind = ":53"
	}

	server := &Server{
		addr:           cfg.Bind,
		tlsAddr:        cfg.BindTLS,
		dohAddr:        cfg.BindDOH,
		tlsCertificate: cfg.TLSCertificate,
		tlsPrivateKey:  cfg.TLSPrivateKey,
		scion:          cfg.SCION,
	}

	server.chainPool.New = func() interface{} {
		return middleware.NewChain(middleware.Handlers())
	}

	return server
}

// ServeDNS implements the Handle interface.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	log.Debug("Handling", "request", r.Question)
	ch := s.chainPool.Get().(*middleware.Chain)

	ch.Reset(w, r)

	ch.Next(context.Background())

	s.chainPool.Put(ch)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handle := func(req *dns.Msg) *dns.Msg {
		mw := mock.NewWriter("tcp", r.RemoteAddr)
		s.ServeDNS(mw, req)

		if !mw.Written() {
			return nil
		}

		return mw.Msg()
	}

	var handlerFn func(http.ResponseWriter, *http.Request)
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handlerFn = doh.HandleJSON(handle)
	} else {
		handlerFn = doh.HandleWireFormat(handle)
	}

	handlerFn(w, r)
}

// Run listen the services
func (s *Server) Run() {
	go s.ListenAndServeDNS("udp")
	go s.ListenAndServeDNS("tcp")
	if s.scion {
		go s.ListenAndServeDNS("scion")
	}
	go s.ListenAndServeDNSTLS()
	go s.ListenAndServeHTTPTLS()
}

// ListenAndServeDNS Starts a server on address and network specified Invoke handler
// for incoming queries.
func (s *Server) ListenAndServeDNS(proto string) {
	log.Info("DNS server listening...", "proto", proto, "addr", s.addr)

	var (
		reuseport = true
		pconn     net.PacketConn
		err       error
		net       string
		addr      string
	)
	if proto == "scion" {
		pconn, err = ListenSQUICPacket(s.addr)
		if err != nil {
			log.Error("DNS listener failed", "proto", proto, "addr", s.addr, "error", err.Error())
		}

		net = "squic"
		addr = s.addr
		reuseport = true
	} else {
		net = proto
		addr = s.addr
	}

	server := &dns.Server{
		Addr: addr,
		Net:  net,
		//Listener:      listener,

		PacketConn:    pconn,
		Handler:       s,
		MaxTCPQueries: 2048,
		ReusePort:     reuseport,
	}

	if net == "squic" {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(s.tlsCertificate, s.tlsPrivateKey)
		if err != nil {
			log.Error("failed to load Cert Files")
			return
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"doq", "dq", "doq-i00", "doq-i02"},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		err = server.ActivateAndServeSQUIC()
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Error("DNS listener failed", "proto", proto, "addr", s.addr, "error", err.Error())
	}
}

func ListenSQUICPacket(address string) (net.PacketConn, error) {

	/*p, err := reuseport.ListenPacket("udp", s.Addr[len(transport.SQUIC+"://"):])
	 if err != nil {
		return nil, err
	 }
	  return p, nil
	*/
	//var ipport netaddr.IPPort
	//var parseerror error
	// s.Addr is something like "squic://:8853" if listening on localhost
	//ipport, parseerror := netaddr.ParseIPPort(s.Addr[len(transport.SQUIC+"://"):])
	//ipport, parseerror := pan.ParseOptionalIPPort(address[len("squic://"):])
	ipport, parseerror := pan.ParseOptionalIPPort(address)
	if parseerror != nil {
		return nil, parseerror
	}

	pconn, e := pan.ListenUDP(context.Background(), ipport, pan.NewDefaultReplySelector())

	if e != nil {
		return nil, e
	}
	return pconn, nil

}

// ListenAndServeDNSTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeDNSTLS() {
	if s.tlsAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "tcp-tls", "addr", s.tlsAddr)

	if err := dns.ListenAndServeTLS(s.tlsAddr, s.tlsCertificate, s.tlsPrivateKey, s); err != nil {
		log.Error("DNS listener failed", "net", "tcp-tls", "addr", s.tlsAddr, "error", err.Error())
	}
}

// ListenAndServeHTTPTLS acts like http.ListenAndServeTLS
func (s *Server) ListenAndServeHTTPTLS() {
	if s.dohAddr == "" {
		return
	}

	log.Info("DNS server listening...", "net", "https", "addr", s.dohAddr)

	logReader, logWriter := io.Pipe()
	go readlogs(logReader)

	srv := &http.Server{
		Addr:         s.dohAddr,
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ErrorLog:     l.New(logWriter, "", 0),
	}

	if err := srv.ListenAndServeTLS(s.tlsCertificate, s.tlsPrivateKey); err != nil {
		log.Error("DNSs listener failed", "net", "https", "addr", s.dohAddr, "error", err.Error())
	}
}

func readlogs(rd io.Reader) {
	buf := bufio.NewReader(rd)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			continue
		}

		parts := strings.SplitN(string(line[:len(line)-1]), " ", 2)
		if len(parts) > 1 {
			log.Warn("Client http socket failed", "net", "https", "error", parts[1])
		}
	}
}

// Package mtls builds the TLS configurations of the server.
//
// The team server has three listeners and they do not need the same
// guarantees:
//
//   - the agent listener takes the agent PSK in the handshake, so TLS is a
//     transport detail there; a certificate is still useful when the traffic
//     has to survive a middlebox.
//   - the operator listener is where mutual TLS pays off: an operator console
//     presents a client certificate, so a stolen token alone is not enough to
//     take over an operation.
//
// The helpers here load the material and build the configurations; they never
// log a key.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Options describes the material of one listener.
type Options struct {
	// The certificate and the private key of the server.
	CertFile string
	KeyFile  string
	// The PEM bundle with the certificate authorities the clients are
	// verified against.  Empty means "do not verify the client".
	ClientCAFile string
	// The name the client certificate must carry.  Empty means "any name".
	ClientCN string
	// Whether a client certificate is required.  It only has an effect when
	// ClientCAFile is set.
	RequireClientCert bool
	// The minimum TLS version.  Empty means TLS 1.2.
	MinVersion string
}

// A Server is a TLS configuration built from a set of files.
type Server struct {
	// The configuration to hand to crypto/tls.
	Config *tls.Config
	// The certificate that was loaded.
	Certificate *tls.Certificate
}

// Load reads the material and builds the configuration.
//
// Nothing is loaded when no certificate is configured: the caller then keeps
// the plain listener, which is the right choice for a lab setup.
func Load(opts Options) (*Server, error) {
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("mtls: a certificate and a key are required")
	}
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load the key pair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	switch opts.MinVersion {
	case "1.3":
		cfg.MinVersion = tls.VersionTLS13
	case "1.2", "":
		cfg.MinVersion = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("mtls: unknown TLS version %q", opts.MinVersion)
	}
	if opts.ClientCAFile != "" {
		pool, err := loadCA(opts.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		if opts.RequireClientCert {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		if opts.ClientCN != "" {
			cfg.VerifyPeerCertificate = verifyCN(opts.ClientCN)
		}
	}
	return &Server{Config: cfg, Certificate: &cert}, nil
}

// loadCA reads a PEM bundle of certificate authorities.
func loadCA(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mtls: read the client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("mtls: %s holds no certificate", filepath.Base(path))
	}
	return pool, nil
}

// verifyCN returns a callback that checks the common name of the peer
// certificate.  The standard verification already proved the chain; this only
// pins the name.
func verifyCN(want string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("mtls: the client sent no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("mtls: the client certificate is unreadable: %w", err)
		}
		if cert.Subject.CommonName != want {
			return fmt.Errorf("mtls: the client certificate is for %q, not %q",
				cert.Subject.CommonName, want)
		}
		return nil
	}
}

// ClientOptions describes the material of a client that talks to a TLS
// listener.
type ClientOptions struct {
	// The certificate and the key the client presents.
	CertFile string
	KeyFile  string
	// The certificate authorities the server is verified against.
	CAFile string
	// The name the server certificate must carry.
	ServerName string
	// Whether the server certificate is verified at all.  It should only be
	// switched off inside a lab.
	Insecure bool
}

// Client builds the configuration of a client that presents a certificate.
func Client(opts ClientOptions) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.Insecure {
		cfg.InsecureSkipVerify = true
	} else if opts.CAFile != "" {
		pool, err := loadCA(opts.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: load the client key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if opts.ServerName != "" {
		cfg.ServerName = opts.ServerName
	}
	return cfg, nil
}

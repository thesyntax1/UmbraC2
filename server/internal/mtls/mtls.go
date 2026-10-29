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
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// The pinned public key of the clients.  It is the hex SHA-256 of the
	// SubjectPublicKeyInfo of the certificate, and it is what a pin is
	// made of: two certificates that carry the same key have the same
	// fingerprint, so a renewed certificate keeps the pin while a
	// certificate that only claims the same name does not.
	//
	// Several pins may be written, separated by commas.  The list is
	// what makes the handover of a renewed key possible: the old pin and
	// the new one are both welcome until the old one is taken away.
	//
	// Empty means "no pin": the chain and the name decide.
	ClientSPKI string
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
	// The certificate is read from the files at every handshake, so a
	// renewed certificate is picked up without a restart.  The pair is
	// cached until one of the files changes.
	cfg.GetCertificate = rotatingCertificate(opts.CertFile, opts.KeyFile, cert)
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
		// The checks on the peer certificate: the chain is proved by
		// the TLS stack, these say *which* certificate of that chain is
		// welcome.
		var checks []func([][]byte, [][]*x509.Certificate) error
		if opts.ClientCN != "" {
			checks = append(checks, verifyCN(opts.ClientCN))
		}
		if pin := strings.TrimSpace(opts.ClientSPKI); pin != "" {
			digests, err := decodePins(pin)
			if err != nil {
				return nil, err
			}
			checks = append(checks, verifySPKI(digests))
			// A pin is a promise about one certificate: a peer that
			// presents none cannot keep it.
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		if len(checks) > 0 {
			cfg.VerifyPeerCertificate = verifyAll(checks)
		}
	}
	return &Server{Config: cfg, Certificate: &cert}, nil
}

// decodePin turns the hex the operator wrote into the bytes of the digest.
func decodePin(pin string) ([]byte, error) {
	raw, err := hex.DecodeString(pin)
	if err != nil {
		return nil, fmt.Errorf("mtls: the pin is not hex: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("mtls: the pin is %d bytes, it must be %d", len(raw), sha256.Size)
	}
	return raw, nil
}

// decodePins turns the list the operator wrote into the bytes of the
// digests.
//
// The list is what a handover needs: the old key and the new one are
// both welcome for a while, and taking the old one away is a matter of
// writing the list again.
func decodePins(pins string) ([][]byte, error) {
	var out [][]byte
	for _, part := range strings.Split(pins, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		digest, err := decodePin(part)
		if err != nil {
			return nil, err
		}
		out = append(out, digest)
	}
	if len(out) == 0 {
		return nil, errors.New("mtls: the pin list is empty")
	}
	return out, nil
}

// verifyAll runs the checks of the peer certificate one after the other.
func verifyAll(checks []func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		for _, check := range checks {
			if err := check(rawCerts, chains); err != nil {
				return err
			}
		}
		return nil
	}
}

// verifySPKI returns a callback that checks the public key of the peer
// certificate against the pins.
//
// The comparison is constant time: the fingerprint is public, but the
// moment a peer is refused says something about the pin, and a
// comparison that leaks the first differing byte is a comparison that
// leaks the pin.  Every pin of the list is compared, so the time the
// check takes does not say which one of them matched.
func verifySPKI(pins [][]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("mtls: the peer sent no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("mtls: the peer certificate is unreadable: %w", err)
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		matched := 0
		for _, pin := range pins {
			if subtle.ConstantTimeCompare(sum[:], pin) == 1 {
				matched = 1
			}
		}
		if matched != 1 {
			return errors.New("mtls: the peer certificate does not hold a pinned key")
		}
		return nil
	}
}

// rotatingCertificate returns a callback that keeps the certificate in
// step with the files on disk.
//
// The callback is called by crypto/tls for every handshake.  It stats the
// two files; when neither changed it hands back the pair it already has,
// and when one of them changed it reads the pair again.  A certificate
// that was renewed on the server is therefore in use after the next
// handshake, with no restart and no dropped connection.
//
// The old certificate is kept when the new one cannot be read: a file that
// is half written must not take the listener down.
func rotatingCertificate(certFile, keyFile string, current tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		mu       sync.Mutex
		cert     = current
		certTime = fileStamp(certFile)
		keyTime  = fileStamp(keyFile)
	)
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		newCertTime := fileStamp(certFile)
		newKeyTime := fileStamp(keyFile)
		if newCertTime == certTime && newKeyTime == keyTime {
			return &cert, nil
		}
		fresh, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			// The files are not usable yet: keep what we have.
			return &cert, nil
		}
		cert = fresh
		certTime, keyTime = newCertTime, newKeyTime
		return &cert, nil
	}
}

// fileStamp is the moment and the size of a file, or the zero time when
// the file cannot be read.
func fileStamp(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.ModTime().UnixNano() ^ info.Size()
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

// SPKIFingerprint returns the pin of a certificate: the hex SHA-256 of its
// SubjectPublicKeyInfo.
//
// It is the same value the server checks, so it is what the operator
// writes into the configuration and into the console.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// SPKIOfFile returns the pin of the first certificate in a PEM file.
//
// The operator runs it on the certificate of the console and on the
// certificate of the server; the answer is what goes into the
// configuration.
func SPKIOfFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("mtls: read the certificate: %w", err)
	}
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("mtls: the certificate is unreadable: %w", err)
		}
		return SPKIFingerprint(cert), nil
	}
	return "", fmt.Errorf("mtls: %s holds no certificate", filepath.Base(path))
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
	// The pinned public key of the server: the hex SHA-256 of the
	// SubjectPublicKeyInfo of its certificate.  Several pins may be
	// written, separated by commas, so a handover of a renewed key is
	// possible: the old pin and the new one are both welcome until the
	// old one is taken away.  When a pin is set the server is accepted
	// only when it holds one of those keys, and the chain is checked as
	// well when a CA file is given.
	//
	// A pin replaces the trust in the authority: a server that presents
	// a certificate of its own, signed by nobody, is accepted when it
	// holds the pinned key.  That is the point of a pin.
	ServerSPKI string
	// Whether the server certificate is verified at all.  It should only be
	// switched off inside a lab.
	Insecure bool
}

// Client builds the configuration of a client that presents a certificate.
func Client(opts ClientOptions) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	var pool *x509.CertPool
	if opts.Insecure {
		cfg.InsecureSkipVerify = true
	} else if opts.CAFile != "" {
		loaded, err := loadCA(opts.CAFile)
		if err != nil {
			return nil, err
		}
		pool = loaded
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
	if pin := strings.TrimSpace(opts.ServerSPKI); pin != "" {
		digests, err := decodePins(pin)
		if err != nil {
			return nil, err
		}
		// The pin is checked by hand, so the standard verification is
		// switched off and the chain is verified inside the callback.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verifyServerPin(digests, pool, opts.ServerName)
	}
	return cfg, nil
}

// verifyServerPin checks the pin of the server certificate, and -- when a
// CA is configured -- the chain of that certificate as well.
//
// The verification is done here because the pin has to be checked even
// when the server certificate is signed by nobody: that is what a pin is
// for.  A CA that is configured is still honoured, so a pin narrows the
// trust and never widens it.
func verifyServerPin(pins [][]byte, pool *x509.CertPool, name string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("mtls: the server sent no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("mtls: the server certificate is unreadable: %w", err)
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		matched := 0
		for _, pin := range pins {
			if subtle.ConstantTimeCompare(sum[:], pin) == 1 {
				matched = 1
			}
		}
		if matched != 1 {
			return errors.New("mtls: the server certificate does not hold a pinned key")
		}
		if pool == nil {
			// No authority to check against: the name is all that is
			// left of the ordinary check.
			if name != "" {
				if err := cert.VerifyHostname(name); err != nil {
					return fmt.Errorf("mtls: the server certificate is not for %q: %w", name, err)
				}
			}
			return nil
		}
		inter := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			chain, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("mtls: the server certificate chain is unreadable: %w", err)
			}
			inter.AddCert(chain)
		}
		opts := x509.VerifyOptions{
			Roots:         pool,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if name != "" {
			opts.DNSName = name
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("mtls: the server certificate is not trusted: %w", err)
		}
		return nil
	}
}

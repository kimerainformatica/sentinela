package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sentinela/internal/model"
)

// NormalizeFingerprint aceita "AB:CD:..." ou "abcd..." e devolve hex minúsculo.
func NormalizeFingerprint(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(fp))
}

// Client fala com o servidor usando TLS com "pinning" do certificado: o
// agente só aceita o certificado cuja impressão digital SHA-256 foi
// informada na instalação. Isso impede interceptação (MITM) mesmo com
// certificado autoassinado.
type Client struct {
	base    string
	agentID string
	secret  string
	pub     ed25519.PublicKey
	http    *http.Client
}

func NewClient(base, fingerprint string) (*Client, error) {
	fp := NormalizeFingerprint(fingerprint)
	if len(fp) != 64 {
		return nil, errors.New("impressão digital do certificado inválida (esperado SHA-256 em hexadecimal)")
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// A validação padrão de cadeia é substituída pela verificação do
		// pin em VerifyPeerCertificate.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("servidor não apresentou certificado")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != fp {
				return errors.New("certificado do servidor não corresponde à impressão digital configurada")
			}
			return nil
		},
	}
	return &Client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
		},
	}, nil
}

func (c *Client) SetCredentials(agentID, secret, pubKeyB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("chave pública de comandos inválida")
	}
	c.agentID, c.secret, c.pub = agentID, secret, pub
	return nil
}

func (c *Client) do(method, path string, body io.Reader, gz bool, out any) error {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}
	if c.agentID != "" {
		req.Header.Set("Authorization", "Bearer "+c.agentID+"."+c.secret)
	}
	req.Header.Set("User-Agent", "sentinela-agent/"+Version)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(out)
	}
	return nil
}

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

func (c *Client) Enroll(token, hostname, osName string) (*model.EnrollResponse, error) {
	var out model.EnrollResponse
	err := c.do("POST", "/agent/v1/enroll", jsonBody(model.EnrollRequest{Token: token, Hostname: hostname, OS: osName}), false, &out)
	return &out, err
}

// GzipReport serializa e comprime um relatório (também usado no spool).
func GzipReport(rep *model.Report) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(rep); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) SendReportGz(data []byte) error {
	return c.do("POST", "/agent/v1/report", bytes.NewReader(data), true, nil)
}

func (c *Client) PollCommands() ([]model.Command, error) {
	var out []model.Command
	err := c.do("GET", "/agent/v1/commands", nil, false, &out)
	return out, err
}

func (c *Client) SendResult(id string, res model.CommandResult) error {
	return c.do("POST", "/agent/v1/commands/"+id+"/result", jsonBody(res), false, nil)
}

// Verify valida a assinatura e a validade de um comando recebido.
func (c *Client) Verify(cmd model.Command) (*model.CommandPayload, error) {
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil || !ed25519.Verify(c.pub, []byte(cmd.Payload), sig) {
		return nil, errors.New("assinatura do comando inválida")
	}
	var p model.CommandPayload
	if err := json.Unmarshal([]byte(cmd.Payload), &p); err != nil {
		return nil, err
	}
	switch {
	case p.ID != cmd.ID:
		return nil, errors.New("ID do comando não confere")
	case p.AgentID != c.agentID:
		return nil, errors.New("comando destinado a outro agente")
	case time.Now().After(p.ExpiresAt):
		return nil, errors.New("comando expirado")
	}
	return &p, nil
}

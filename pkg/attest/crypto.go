package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// GenerateKey 生成一对 ed25519 签名密钥。
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// KeyID 是公钥的稳定标识 (公钥摘要的前 8 字节)。
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func SavePrivateKey(path string, priv ed25519.PrivateKey) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0o600)
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad private key length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

func SavePublicKey(path string, pub ed25519.PublicKey) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(pub)), 0o644)
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// SignStatement 用确定性 JSON 序列化 Statement 并签名。
// Go 的 encoding/json 对 struct 字段顺序固定、对 map 键排序, 因此序列化是规范化的。
func SignStatement(st *Statement, keyID string, priv ed25519.PrivateKey) (*Envelope, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, payload)
	return &Envelope{
		PayloadType: "application/vnd.provchain.statement+json",
		Payload:     payload,
		Signatures:  []Signature{{KeyID: keyID, Sig: sig}},
	}, nil
}

// VerifyEnvelope 验证 Envelope 上是否有任一受信密钥的有效签名, 并解出 Statement。
func VerifyEnvelope(env *Envelope, trusted map[string]ed25519.PublicKey) (*Statement, error) {
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("envelope has no signatures")
	}
	for _, s := range env.Signatures {
		pub, ok := trusted[s.KeyID]
		if !ok {
			continue // 不是受信密钥签的
		}
		if ed25519.Verify(pub, env.Payload, s.Sig) {
			var st Statement
			if err := json.Unmarshal(env.Payload, &st); err != nil {
				return nil, fmt.Errorf("corrupt statement payload: %w", err)
			}
			return &st, nil
		}
	}
	return nil, fmt.Errorf("no valid signature from a trusted key")
}

// Package attest 定义来源证明(attestation)的核心数据结构。
// 数据模型借鉴 in-toto: 每个流水线步骤产生一条 Statement,
// 谓词(predicate)是一条 Link, 记录该步骤的输入(materials)、命令、环境,
// Statement 的 subject 是该步骤产物的摘要。签名后的 Statement 包在 Envelope 里。
package attest

// StatementType 标识 Statement 的版本化 schema。
const StatementType = "https://provchain.dev/Statement/v1"

// Resource 是一个被摘要标识的产物或材料。
type Resource struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"` // 例如 {"sha256": "ab12..."}
}

// Link 描述流水线中的一个步骤: 谁、用什么输入、执行了什么命令、在什么环境下。
type Link struct {
	Name        string            `json:"name"`
	Builder     string            `json:"builder"`
	Command     []string          `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Materials   []Resource        `json:"materials"` // 输入: 源码快照、依赖、上一步产物
}

// Statement = subject(产物) + predicate(Link)。
type Statement struct {
	Type      string   `json:"_type"`
	Subject   Resource `json:"subject"`
	Predicate Link     `json:"predicate"`
}

// Signature 是一处签名, keyid 指向验证用的公钥。
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// Envelope 是签名后的 Statement (类 DSSE)。
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"` // 序列化后的 Statement
	Signatures  []Signature `json:"signatures"`
}

// Bundle 是一条完整流水线的全部 Envelope, 按步骤顺序排列, 随产物一起发布。
type Bundle struct {
	Envelopes []*Envelope `json:"envelopes"`
}

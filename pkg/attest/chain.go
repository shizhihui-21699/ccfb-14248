package attest

import (
	"crypto/ed25519"
	"fmt"
)

// VerifyChain 验证一条完整的 attestation 链:
//  1. 每个 Envelope 都有受信密钥的有效签名;
//  2. 步骤序列与期望的流水线完全一致 (不能跳步、乱序、重放);
//  3. 每一步的 materials 必须引用上一步的 subject 摘要 (链式衔接)。
//
// 返回按顺序解出的 Statement 列表。
func VerifyChain(b *Bundle, trusted map[string]ed25519.PublicKey, expectedSteps []string) ([]*Statement, error) {
	if len(b.Envelopes) != len(expectedSteps) {
		return nil, fmt.Errorf("chain has %d links, expected %d steps — steps were added or removed",
			len(b.Envelopes), len(expectedSteps))
	}
	stmts := make([]*Statement, 0, len(b.Envelopes))
	for i, env := range b.Envelopes {
		st, err := VerifyEnvelope(env, trusted)
		if err != nil {
			return nil, fmt.Errorf("link %d (%s): %w", i, expectedSteps[i], err)
		}
		if st.Predicate.Name != expectedSteps[i] {
			return nil, fmt.Errorf("link %d is step %q, expected %q — pipeline order violated",
				i, st.Predicate.Name, expectedSteps[i])
		}
		if i > 0 {
			prevDigest := stmts[i-1].Subject.Digest["sha256"]
			linked := false
			for _, m := range st.Predicate.Materials {
				if m.Digest["sha256"] == prevDigest {
					linked = true
					break
				}
			}
			if !linked {
				return nil, fmt.Errorf("link %d (%s) does not consume the product of step %q — chain is broken",
					i, st.Predicate.Name, expectedSteps[i-1])
			}
		}
		stmts = append(stmts, st)
	}
	return stmts, nil
}

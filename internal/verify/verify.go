// Package verify 是客户侧的独立核验器。客户拿到产物和证明链后,
// 只信任: 签名服务的公钥 + 开发者提交的 lockfile + 内容寻址存储。
// 核验内容:
//  1. 链上每条 Statement 都有受信密钥的有效签名;
//  2. 步骤序列完整有序, 逐步衔接(不能跳步/乱序/塞入外来环节);
//  3. 到手的产物摘要 == 链尾签名的产物摘要;
//  4. 依赖逐条等于 lockfile;
//  5. 包内二进制 == build 环节签名的产物;
//  6. (可选)客户自己从 CAS 取源码和依赖独立重建, 逐字节比对。
package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"provchain/internal/buildx"
	"provchain/internal/cas"
	"provchain/internal/pipeline"
	"provchain/pkg/attest"
)

type Options struct {
	ArtifactPath string
	BundlePath   string
	PublicKey    ed25519.PublicKey
	Lockfile     map[string]string
	CAS          *cas.Store
	Rebuild      bool // 是否执行独立重建(最强核验)
	Logf         func(format string, args ...any)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func Run(o *Options) error {
	logf := func(format string, args ...any) {
		if o.Logf != nil {
			o.Logf(format, args...)
		}
	}

	data, err := os.ReadFile(o.BundlePath)
	if err != nil {
		return err
	}
	var bundle attest.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("corrupt attestation bundle: %w", err)
	}

	trusted := map[string]ed25519.PublicKey{attest.KeyID(o.PublicKey): o.PublicKey}

	// 1+2: 签名有效 & 链完整有序
	stmts, err := attest.VerifyChain(&bundle, trusted, pipeline.Steps)
	if err != nil {
		return fmt.Errorf("attestation chain invalid: %w", err)
	}
	logf("  ✔ 证明链签名有效, %d 个步骤完整衔接 (%s)", len(stmts), strings.Join(pipeline.Steps, " → "))

	// 3: 到手的产物 == 链尾签名的产物
	artDigest, err := buildx.HashFile(o.ArtifactPath)
	if err != nil {
		return err
	}
	final := stmts[len(stmts)-1]
	if artDigest != final.Subject.Digest["sha256"] {
		return fmt.Errorf("artifact sha256=%s… does NOT match attested product %s… — artifact was replaced after signing",
			short(artDigest), short(final.Subject.Digest["sha256"]))
	}
	logf("  ✔ 产物摘要与链尾签名一致 sha256=%s…", short(artDigest))

	// 4: 依赖逐条等于 lockfile
	for _, st := range stmts {
		if st.Predicate.Name != "resolve-deps" {
			continue
		}
		for _, m := range st.Predicate.Materials {
			name, ok := strings.CutPrefix(m.Name, "dep:")
			if !ok {
				continue
			}
			if o.Lockfile[name] != m.Digest["sha256"] {
				return fmt.Errorf("dependency %s does not match lockfile", name)
			}
			logf("  ✔ 依赖 %s 与 lockfile 一致 sha256=%s…", name, short(m.Digest["sha256"]))
		}
	}

	// 5: 包内二进制 == build 环节签名的产物
	tmp, err := os.MkdirTemp("", "customer-verify")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	artBytes, err := os.ReadFile(o.ArtifactPath)
	if err != nil {
		return err
	}
	if err := buildx.UntarGz(artBytes, tmp); err != nil {
		return fmt.Errorf("cannot extract artifact: %w", err)
	}
	binDigest, err := buildx.HashFile(filepath.Join(tmp, "app"))
	if err != nil {
		return err
	}
	buildStmt := stmts[2] // "build"
	if binDigest != buildStmt.Subject.Digest["sha256"] {
		return fmt.Errorf("packaged binary does not match the build-step attestation")
	}
	logf("  ✔ 包内二进制与 build 步骤签名一致 sha256=%s…", short(binDigest))

	// 6: 独立重建
	if o.Rebuild {
		var srcDigest, manifestDigest string
		for _, m := range buildStmt.Predicate.Materials {
			switch m.Name {
			case "source-snapshot":
				srcDigest = m.Digest["sha256"]
			case "deps-manifest":
				manifestDigest = m.Digest["sha256"]
			}
		}
		manifestBytes, err := o.CAS.Get(manifestDigest)
		if err != nil {
			return err
		}
		var manifest map[string]string
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			return err
		}
		out := filepath.Join(tmp, "rebuilt")
		if err := pipeline.RebuildFromCAS(o.CAS, srcDigest, manifest, out); err != nil {
			return fmt.Errorf("independent rebuild failed: %w", err)
		}
		rebuilt, err := buildx.HashFile(out)
		if err != nil {
			return err
		}
		if rebuilt != binDigest {
			return fmt.Errorf("independent rebuild sha256=%s… does NOT match shipped binary %s…",
				short(rebuilt), short(binDigest))
		}
		logf("  ✔ 客户独立重建结果与发布二进制逐字节一致")
	}
	return nil
}

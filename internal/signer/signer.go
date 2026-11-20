// Package signer 是独立的"核验签名服务"。它持有签名私钥(构建机上没有),
// 构建机每完成一步就提交一份构建报告(Report), 签名服务按策略核验后才签名:
//
//   - fetch-source: 记录源码快照摘要;
//   - resolve-deps: 每个依赖的摘要必须等于 lockfile 锁定的值;
//   - build:        所有材料必须是本服务此前签过名的产物(防链外材料),
//     并且签名服务从 CAS 取出源码快照和锁定的依赖,
//     在干净环境里独立重建, 产物摘要必须逐字节一致 ——
//     构建机被攻破、构建中途被掉包, 都会在这里暴露;
//   - package:      打包的必须是此前签过名的产物。
//
// 签名服务维护一份已签发 Statement 的日志(按产物摘要索引),
// 这就是多级流水线能"串起来"的锚点。
package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"provchain/internal/buildx"
	"provchain/internal/cas"
	"provchain/pkg/attest"
)

// RebuildFunc 在给定源码快照摘要和依赖(名称->摘要)后, 独立重建产物到 outPath。
type RebuildFunc func(sourceDigest string, deps map[string]string, outPath string) error

type Service struct {
	KeyID    string
	priv     ed25519.PrivateKey
	cas      *cas.Store
	lockfile map[string]string // 依赖名 -> 锁定的 sha256
	rebuild  RebuildFunc
	log      map[string]*attest.Statement // 已签发产物摘要 -> Statement
}

func New(priv ed25519.PrivateKey, store *cas.Store, lockfile map[string]string, rebuild RebuildFunc) *Service {
	return &Service{
		KeyID:    attest.KeyID(priv.Public().(ed25519.PublicKey)),
		priv:     priv,
		cas:      store,
		lockfile: lockfile,
		rebuild:  rebuild,
		log:      map[string]*attest.Statement{},
	}
}

// Report 是构建机提交给签名服务的一步构建报告。
type Report struct {
	Step        string
	BuilderID   string
	Command     []string
	Env         map[string]string
	Materials   []attest.Resource
	ProductPath string // 构建机上的产物文件, 签名服务自己重新算摘要
}

// Attest 核验报告, 通过则签发 Envelope, 否则拒绝。
func (s *Service) Attest(rep *Report) (*attest.Envelope, error) {
	prodDigest, err := buildx.HashFile(rep.ProductPath)
	if err != nil {
		return nil, fmt.Errorf("signer cannot read claimed product: %w", err)
	}

	switch rep.Step {
	case "fetch-source":
		// 记录源码快照, 无需进一步检查。

	case "resolve-deps":
		for _, m := range rep.Materials {
			name, ok := strings.CutPrefix(m.Name, "dep:")
			if !ok {
				continue
			}
			want, declared := s.lockfile[name]
			if !declared {
				return nil, fmt.Errorf("undeclared dependency %q — not in lockfile", name)
			}
			if got := m.Digest["sha256"]; got != want {
				return nil, fmt.Errorf("dependency %s digest %s… != lockfile %s… — refusing to sign",
					name, short(got), short(want))
			}
		}

	case "build":
		if err := s.checkBuild(rep, prodDigest); err != nil {
			return nil, err
		}

	case "package":
		ok := false
		for _, m := range rep.Materials {
			if _, signed := s.log[m.Digest["sha256"]]; signed {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("package materials were never attested — refusing to sign")
		}

	default:
		return nil, fmt.Errorf("unknown pipeline step %q", rep.Step)
	}

	st := &attest.Statement{
		Type:    attest.StatementType,
		Subject: attest.Resource{Name: filepath.Base(rep.ProductPath), Digest: map[string]string{"sha256": prodDigest}},
		Predicate: attest.Link{
			Name:        rep.Step,
			Builder:     rep.BuilderID,
			Command:     rep.Command,
			Environment: rep.Env,
			Materials:   rep.Materials,
		},
	}
	env, err := attest.SignStatement(st, s.KeyID, s.priv)
	if err != nil {
		return nil, err
	}
	s.log[prodDigest] = st
	return env, nil
}

// checkBuild 是 build 步骤的核心策略: 链上材料检查 + 独立重建比对。
func (s *Service) checkBuild(rep *Report, prodDigest string) error {
	var sourceDigest, manifestDigest string
	for _, m := range rep.Materials {
		d := m.Digest["sha256"]
		if _, signed := s.log[d]; !signed {
			return fmt.Errorf("build material %q (%s…) was never attested by this service — possible chain forgery",
				m.Name, short(d))
		}
		switch m.Name {
		case "source-snapshot":
			sourceDigest = d
		case "deps-manifest":
			manifestDigest = d
		}
	}
	if sourceDigest == "" || manifestDigest == "" {
		return fmt.Errorf("build report must reference source-snapshot and deps-manifest")
	}

	// 依赖清单必须逐条等于 lockfile。
	manifestBytes, err := s.cas.Get(manifestDigest)
	if err != nil {
		return err
	}
	var manifest map[string]string
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("corrupt deps manifest: %w", err)
	}
	for name, d := range manifest {
		if s.lockfile[name] != d {
			return fmt.Errorf("dependency %s in manifest does not match lockfile — refusing to sign", name)
		}
	}

	// 独立重建: 从 CAS 取已 attest 的源码和依赖, 在干净目录里重新编译。
	tmp, err := os.MkdirTemp("", "signer-rebuild")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "rebuilt")
	if err := s.rebuild(sourceDigest, manifest, out); err != nil {
		return fmt.Errorf("independent rebuild failed: %w", err)
	}
	rebuilt, err := buildx.HashFile(out)
	if err != nil {
		return err
	}
	if rebuilt != prodDigest {
		return fmt.Errorf("independent rebuild mismatch: builder claims sha256=%s… but signer reproduced sha256=%s… — REFUSING to sign (build machine output was tampered)",
			short(prodDigest), short(rebuilt))
	}
	return nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

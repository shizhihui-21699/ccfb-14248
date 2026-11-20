// Package attacks 搭建演示世界(World)并实现四种篡改场景,
// 每种场景都走真实的流水线/签名/核验代码, 观察是否被识破。
package attacks

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"provchain/internal/buildx"
	"provchain/internal/cas"
	"provchain/internal/pipeline"
	"provchain/internal/signer"
	"provchain/internal/verify"
	"provchain/pkg/attest"
)

// World 是一次演示的运行环境。
type World struct {
	Root     string
	Pub      ed25519.PublicKey
	Lockfile map[string]string
}

func (w *World) store() *cas.Store {
	s, _ := cas.New(filepath.Join(w.Root, "cas"))
	return s
}

// newSigner 每次流水线运行都新建签名服务(已签发日志随之重置)。
// 私钥只出现在 keys/ 下, 构建机目录里没有。
func (w *World) newSigner() *signer.Service {
	priv, err := attest.LoadPrivateKey(filepath.Join(w.Root, "keys", "signer.key"))
	if err != nil {
		panic(err)
	}
	store := w.store()
	return signer.New(priv, store, w.Lockfile, func(src string, deps map[string]string, out string) error {
		return pipeline.RebuildFromCAS(store, src, deps, out)
	})
}

// RunPipeline 跑一遍四级流水线。
func (w *World) RunPipeline(t *pipeline.Tamper, logf func(string, ...any)) (*pipeline.Result, error) {
	p := &pipeline.Pipeline{
		Root:     w.Root,
		Signer:   w.newSigner(),
		CAS:      w.store(),
		Lockfile: w.Lockfile,
		Tamper:   t,
		Logf:     logf,
	}
	return p.Run()
}

// Verify 客户侧核验。
func (w *World) Verify(artifact, bundle string, rebuild bool, logf func(string, ...any)) error {
	return verify.Run(&verify.Options{
		ArtifactPath: artifact,
		BundlePath:   bundle,
		PublicKey:    w.Pub,
		Lockfile:     w.Lockfile,
		CAS:          w.store(),
		Rebuild:      rebuild,
		Logf:         logf,
	})
}

// buildEvilBinary 攻击者用同一套源码+依赖编一个植入后门的二进制。
func (w *World) buildEvilBinary() (string, error) {
	dir := filepath.Join(w.Root, "attacker", "evil-src")
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := buildx.CopyDir(filepath.Join(w.Root, "repo"), dir); err != nil {
		return "", err
	}
	mainPath := filepath.Join(dir, "main.go")
	b, err := os.ReadFile(mainPath)
	if err != nil {
		return "", err
	}
	b = bytes.Replace(b, []byte(`"1.0.0"`), []byte(`"1.0.0-backdoored"`), 1)
	if err := os.WriteFile(mainPath, b, 0o644); err != nil {
		return "", err
	}
	assetsDir := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		return "", err
	}
	if err := buildx.Copy(filepath.Join(w.Root, "registry", "config.json"),
		filepath.Join(assetsDir, "config.json")); err != nil {
		return "", err
	}
	out := filepath.Join(w.Root, "attacker", "evil-app")
	if err := buildx.GoBuild(dir, out); err != nil {
		return "", err
	}
	return out, nil
}

// bumpVersion 修改仓库里的版本号(模拟另一次诚实的发布)。
func (w *World) bumpVersion(from, to string) error {
	mainPath := filepath.Join(w.Root, "repo", "main.go")
	b, err := os.ReadFile(mainPath)
	if err != nil {
		return err
	}
	b = bytes.Replace(b, []byte(`"`+from+`"`), []byte(`"`+to+`"`), 1)
	return os.WriteFile(mainPath, b, 0o644)
}

// ---------------------------------------------------------------------------
// 场景 1: 传输/发布环节产物被掉包 (构建和签名都是诚实的)
// ---------------------------------------------------------------------------
func SwapArtifact(w *World) (detected bool, detail string, err error) {
	res, err := w.RunPipeline(nil, nil)
	if err != nil {
		return false, "", err
	}
	evilBin, err := w.buildEvilBinary()
	if err != nil {
		return false, "", err
	}
	evilPkg, err := buildx.TarGzFiles([]buildx.Entry{
		{Name: "app", Path: evilBin},
		{Name: "LICENSE", Path: filepath.Join(w.Root, "repo", "LICENSE")},
	})
	if err != nil {
		return false, "", err
	}
	// 攻击者替换发布产物, 证明链文件原样保留。
	if err := os.WriteFile(res.ArtifactPath, evilPkg, 0o644); err != nil {
		return false, "", err
	}
	vErr := w.Verify(res.ArtifactPath, res.BundlePath, true, nil)
	if vErr != nil {
		return true, vErr.Error(), nil
	}
	return false, "被掉包的产物竟然通过了核验!", nil
}

// ---------------------------------------------------------------------------
// 场景 2: 构建机被攻破
//
//	2a. 构建机编译后把二进制换成后门版, 再拿去给签名服务签名
//	2b. 构建机干脆自己生成密钥, 伪造一份"证明"
//
// ---------------------------------------------------------------------------
func CompromisedBuilder(w *World) (detected bool, detail string, err error) {
	// 2a: 掉包产物后请求签名 -> 签名服务独立重建比对, 应当拒签
	tamper := &pipeline.Tamper{AfterBuild: func(binPath string) {
		if evil, e := w.buildEvilBinary(); e == nil {
			_ = buildx.Copy(evil, binPath)
		}
	}}
	_, errA := w.RunPipeline(tamper, nil)
	detectedA := errA != nil && strings.Contains(errA.Error(), "rebuild mismatch")

	// 2b: 构建机伪造证明 -> 客户只信签名服务公钥, 应当验签失败
	res, err := w.RunPipeline(nil, nil)
	if err != nil {
		return false, "", err
	}
	evilBin, err := w.buildEvilBinary()
	if err != nil {
		return false, "", err
	}
	evilDigest, _ := buildx.HashFile(evilBin)
	forged := &attest.Statement{
		Type:    attest.StatementType,
		Subject: attest.Resource{Name: "app", Digest: map[string]string{"sha256": evilDigest}},
		Predicate: attest.Link{
			Name:    "build",
			Builder: "builder-01",
		},
	}
	attackerPub, attackerPriv, _ := attest.GenerateKey()
	forgedEnv, _ := attest.SignStatement(forged, attest.KeyID(attackerPub), attackerPriv)

	var bundle attest.Bundle
	data, _ := os.ReadFile(res.BundlePath)
	_ = json.Unmarshal(data, &bundle)
	bundle.Envelopes[2] = forgedEnv // 把 build 环节换成伪造的
	forgedPath := filepath.Join(w.Root, "dist", "forged.bundle.json")
	forgedJSON, _ := json.MarshalIndent(bundle, "", "  ")
	if err := os.WriteFile(forgedPath, forgedJSON, 0o644); err != nil {
		return false, "", err
	}
	errB := w.Verify(res.ArtifactPath, forgedPath, false, nil)
	detectedB := errB != nil

	switch {
	case detectedA && detectedB:
		return true, fmt.Sprintf("2a 拒签: %v; 2b 伪造证明验签失败: %v", errA, errB), nil
	case !detectedA:
		return false, "构建机掉包产物后仍获得了签名!", nil
	default:
		return false, "构建机伪造的证明竟然通过了核验!", nil
	}
}

// ---------------------------------------------------------------------------
// 场景 3: 依赖被临时替换
//
//	3a. 依赖仓库在拉取前就被污染 -> lockfile 校验应当当场拦下
//	3b. 依赖在 lockfile 校验之后、编译之前被掉包 -> 签名服务重建比对应当识破
//
// ---------------------------------------------------------------------------
func SwapDependency(w *World) (detected bool, detail string, err error) {
	regPath := filepath.Join(w.Root, "registry", "config.json")
	orig, err := os.ReadFile(regPath)
	if err != nil {
		return false, "", err
	}
	evil := []byte(`{"feature":"backdoor","ui_theme":"dark"}`)

	// 3a: 拉取前污染依赖仓库
	if err := os.WriteFile(regPath, evil, 0o644); err != nil {
		return false, "", err
	}
	_, errA := w.RunPipeline(nil, nil)
	_ = os.WriteFile(regPath, orig, 0o644) // 恢复
	detectedA := errA != nil && strings.Contains(errA.Error(), "lockfile")

	// 3b: lockfile 校验通过后、编译前掉包构建目录里的依赖
	tamper := &pipeline.Tamper{AfterAssemble: func(buildDir string) {
		_ = os.WriteFile(filepath.Join(buildDir, "assets", "config.json"), evil, 0o644)
	}}
	_, errB := w.RunPipeline(tamper, nil)
	detectedB := errB != nil && strings.Contains(errB.Error(), "rebuild mismatch")

	switch {
	case detectedA && detectedB:
		return true, fmt.Sprintf("3a lockfile 拦截: %v; 3b 重建比对识破: %v", errA, errB), nil
	case !detectedA:
		return false, "被污染的依赖通过了 lockfile 校验!", nil
	default:
		return false, "编译前掉包依赖仍获得了签名!", nil
	}
}

// ---------------------------------------------------------------------------
// 场景 4: 证明链被拼接/重放
//
//	攻击者把另一次诚实发布(不同版本)的 build 环节塞进本次证明链,
//	所有签名都是真的, 但链式衔接应当断裂。
//
// ---------------------------------------------------------------------------
func BreakChain(w *World) (detected bool, detail string, err error) {
	resA, err := w.RunPipeline(nil, nil)
	if err != nil {
		return false, "", err
	}
	bundleA, _ := os.ReadFile(resA.BundlePath)

	// 另一次诚实发布: 版本号 1.0.0 -> 1.0.1
	if err := w.bumpVersion("1.0.0", "1.0.1"); err != nil {
		return false, "", err
	}
	resB, err := w.RunPipeline(nil, nil)
	_ = w.bumpVersion("1.0.1", "1.0.0") // 恢复
	if err != nil {
		return false, "", err
	}
	bundleB, _ := os.ReadFile(resB.BundlePath)

	var a, b attest.Bundle
	_ = json.Unmarshal(bundleA, &a)
	_ = json.Unmarshal(bundleB, &b)

	// 拼接: A 的链 + B 的 build 环节 (签名全部真实有效)
	a.Envelopes[2] = b.Envelopes[2]
	splicedPath := filepath.Join(w.Root, "dist", "spliced.bundle.json")
	splicedJSON, _ := json.MarshalIndent(a, "", "  ")
	if err := os.WriteFile(splicedPath, splicedJSON, 0o644); err != nil {
		return false, "", err
	}
	errSplice := w.Verify(resB.ArtifactPath, splicedPath, false, nil)
	detectedSplice := errSplice != nil && strings.Contains(errSplice.Error(), "chain")

	// 重放: 拿旧版本 A 的链去配新版本 B 的产物
	bundleAPath := filepath.Join(w.Root, "attacker", "bundleA.json")
	if err := os.MkdirAll(filepath.Dir(bundleAPath), 0o755); err != nil {
		return false, "", err
	}
	if err := os.WriteFile(bundleAPath, bundleA, 0o644); err != nil {
		return false, "", err
	}
	errReplay := w.Verify(resB.ArtifactPath, bundleAPath, false, nil)
	detectedReplay := errReplay != nil

	switch {
	case detectedSplice && detectedReplay:
		return true, fmt.Sprintf("拼接链被拒: %v; 旧链配新产物被拒: %v", errSplice, errReplay), nil
	case !detectedSplice:
		return false, "拼接的证明链竟然通过了核验!", nil
	default:
		return false, "旧证明链配新产物竟然通过了核验!", nil
	}
}

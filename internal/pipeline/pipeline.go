// Package pipeline 模拟一条四级发布流水线:
//
//	fetch-source  源码快照(内容寻址存证)
//	resolve-deps  按 lockfile 取依赖并校验
//	build         可复现编译
//	package       确定性打包
//
// 每一步的产物都提交给独立签名服务 attest, 形成一条可验证的链。
// 构建机本身不持有任何签名密钥。
package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"provchain/internal/buildx"
	"provchain/internal/cas"
	"provchain/internal/signer"
	"provchain/pkg/attest"
)

// Steps 是流水线的标准步骤序列, 客户端核验时以此为基准。
var Steps = []string{"fetch-source", "resolve-deps", "build", "package"}

// Tamper 给攻击场景预留的"构建机被攻破"钩子。
type Tamper struct {
	AfterAssemble func(buildDir string) // 源码+依赖组装完、编译前
	AfterBuild    func(binPath string)  // 编译完、提交报告前
}

type Pipeline struct {
	Root     string
	Signer   *signer.Service
	CAS      *cas.Store
	Lockfile map[string]string
	Tamper   *Tamper
	Logf     func(format string, args ...any)

	bundle []*attest.Envelope
}

type Result struct {
	ArtifactPath string
	BundlePath   string
	BinaryDigest string
	Bundle       []*attest.Envelope
}

func res(name, digest string) attest.Resource {
	return attest.Resource{Name: name, Digest: map[string]string{"sha256": digest}}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func (p *Pipeline) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

// attest 把一步的构建报告提交给签名服务; 被拒则整条流水线中止。
func (p *Pipeline) attest(step string, materials []attest.Resource, productPath string, command []string, env map[string]string) error {
	rep := &signer.Report{
		Step:        step,
		BuilderID:   "builder-01",
		Command:     command,
		Env:         env,
		Materials:   materials,
		ProductPath: productPath,
	}
	env1, err := p.Signer.Attest(rep)
	if err != nil {
		return fmt.Errorf("step %s: attestation REFUSED by signer: %w", step, err)
	}
	digest, _ := buildx.HashFile(productPath)
	p.logf("  ✔ %-13s 已签发, 产物 sha256=%s…", step, short(digest))
	p.bundle = append(p.bundle, env1)
	return nil
}

// Run 执行完整流水线。
func (p *Pipeline) Run() (*Result, error) {
	builderDir := filepath.Join(p.Root, "builder")
	distDir := filepath.Join(p.Root, "dist")
	for _, d := range []string{builderDir, distDir} {
		if err := os.RemoveAll(d); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	repoDir := filepath.Join(p.Root, "repo")

	// ---------- Step 1: fetch-source ----------
	snapshot, err := buildx.TarGzDir(repoDir)
	if err != nil {
		return nil, err
	}
	snapDigest, err := p.CAS.Put(snapshot)
	if err != nil {
		return nil, err
	}
	snapPath := filepath.Join(builderDir, "source-snapshot.tar.gz")
	if err := os.WriteFile(snapPath, snapshot, 0o644); err != nil {
		return nil, err
	}
	if err := p.attest("fetch-source", nil, snapPath, nil, nil); err != nil {
		return nil, err
	}

	// ---------- Step 2: resolve-deps ----------
	manifest := map[string]string{}
	materials := []attest.Resource{res("source-snapshot", snapDigest)}
	names := make([]string, 0, len(p.Lockfile))
	for name := range p.Lockfile {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(p.Root, "registry", name))
		if err != nil {
			return nil, fmt.Errorf("fetch dependency %s: %w", name, err)
		}
		got := buildx.SHA256Bytes(data)
		if want := p.Lockfile[name]; got != want {
			return nil, fmt.Errorf("dependency %s failed lockfile check: got sha256=%s…, lockfile pins %s… — build aborted",
				name, short(got), short(want))
		}
		if _, err := p.CAS.Put(data); err != nil {
			return nil, err
		}
		manifest[name] = got
		materials = append(materials, res("dep:"+name, got))
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestDigest, err := p.CAS.Put(manifestBytes)
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(builderDir, "deps-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		return nil, err
	}
	if err := p.attest("resolve-deps", materials, manifestPath, nil, nil); err != nil {
		return nil, err
	}

	// ---------- Step 3: build ----------
	buildDir := filepath.Join(builderDir, "src")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return nil, err
	}
	if err := buildx.UntarGz(snapshot, buildDir); err != nil {
		return nil, err
	}
	assetsDir := filepath.Join(buildDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		return nil, err
	}
	for name, d := range manifest {
		data, err := p.CAS.Get(d)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(assetsDir, name), data, 0o644); err != nil {
			return nil, err
		}
	}
	if p.Tamper != nil && p.Tamper.AfterAssemble != nil {
		p.Tamper.AfterAssemble(buildDir) // 攻击钩子: 编译前掉包
	}
	binPath := filepath.Join(builderDir, "app")
	cmdline := []string{"go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", "app", "."}
	if err := buildx.GoBuild(buildDir, binPath); err != nil {
		return nil, err
	}
	if p.Tamper != nil && p.Tamper.AfterBuild != nil {
		p.Tamper.AfterBuild(binPath) // 攻击钩子: 编译后掉包
	}
	env := map[string]string{
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"toolchain": buildx.GoVersion(),
	}
	buildMaterials := []attest.Resource{res("source-snapshot", snapDigest), res("deps-manifest", manifestDigest)}
	if err := p.attest("build", buildMaterials, binPath, cmdline, env); err != nil {
		return nil, err
	}
	binDigest, _ := buildx.HashFile(binPath)

	// ---------- Step 4: package ----------
	pkgBytes, err := buildx.TarGzFiles([]buildx.Entry{
		{Name: "app", Path: binPath},
		{Name: "LICENSE", Path: filepath.Join(repoDir, "LICENSE")},
	})
	if err != nil {
		return nil, err
	}
	pkgPath := filepath.Join(distDir, "app.tar.gz")
	if err := os.WriteFile(pkgPath, pkgBytes, 0o644); err != nil {
		return nil, err
	}
	if err := p.attest("package", []attest.Resource{res("app-binary", binDigest)}, pkgPath, nil, nil); err != nil {
		return nil, err
	}

	bundlePath := filepath.Join(distDir, "attestation.bundle.json")
	bundleJSON, _ := json.MarshalIndent(attest.Bundle{Envelopes: p.bundle}, "", "  ")
	if err := os.WriteFile(bundlePath, bundleJSON, 0o644); err != nil {
		return nil, err
	}
	p.logf("  发布产物: %s\n  证明链:   %s", pkgPath, bundlePath)

	return &Result{
		ArtifactPath: pkgPath,
		BundlePath:   bundlePath,
		BinaryDigest: binDigest,
		Bundle:       p.bundle,
	}, nil
}

// RebuildFromCAS 供签名服务和客户核验共用: 按 attestation 里记录的
// 源码快照摘要和依赖清单, 从 CAS 取料, 在干净目录里独立重建。
func RebuildFromCAS(store *cas.Store, sourceDigest string, deps map[string]string, outPath string) error {
	tmp, err := os.MkdirTemp("", "rebuild")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	snapshot, err := store.Get(sourceDigest)
	if err != nil {
		return err
	}
	if err := buildx.UntarGz(snapshot, tmp); err != nil {
		return err
	}
	if len(deps) > 0 {
		assetsDir := filepath.Join(tmp, "assets")
		if err := os.MkdirAll(assetsDir, 0o755); err != nil {
			return err
		}
		for name, d := range deps {
			data, err := store.Get(d)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(assetsDir, name), data, 0o644); err != nil {
				return err
			}
		}
	}
	return buildx.GoBuild(tmp, outPath)
}

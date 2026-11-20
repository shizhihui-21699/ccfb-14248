// provdemo 演示一套构建来源证明体系:
//
//	provdemo demo     完整演示: 诚实流水线 + 客户核验 + 可复现性 + 全部篡改场景
//	provdemo run      只跑诚实流水线并做客户核验
//	provdemo attacks  只跑篡改场景
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"provchain/internal/attacks"
	"provchain/internal/buildx"
	"provchain/pkg/attest"
)

const productMain = `package main

import (
	_ "embed"
	"fmt"
)

//go:embed assets/config.json
var config []byte

const version = "1.0.0"

func main() {
	fmt.Printf("demo-app %s config=%s", version, string(config))
}
`

const productGoMod = `module demoapp

go 1.21
`

const productLicense = "MIT License\n\nCopyright (c) 2026 Example Corp\n"

const registryConfig = `{"feature":"standard","ui_theme":"light"}`

func main() {
	cmd := "demo"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	root := "demo-run"

	var err error
	switch cmd {
	case "demo":
		err = runDemo(root)
	case "run":
		err = runHonest(root)
	case "attacks":
		err = runAttacks(root)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (demo|run|attacks)\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ 演示失败: %v\n", err)
		os.Exit(1)
	}
}

// setup 搭建演示世界: 源码仓库、依赖仓库、lockfile、签名密钥(只在 keys/ 下)。
func setup(root string) (*attacks.World, error) {
	if err := os.RemoveAll(root); err != nil {
		return nil, err
	}
	for _, d := range []string{"repo", "registry", "keys", "cas", "attacker"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	files := map[string]string{
		"repo/main.go":         productMain,
		"repo/go.mod":          productGoMod,
		"repo/LICENSE":         productLicense,
		"registry/config.json": registryConfig,
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	// lockfile: 开发者锁定依赖摘要(现实中随源码一起提交、评审)
	lockfile := map[string]string{}
	depBytes, _ := os.ReadFile(filepath.Join(root, "registry", "config.json"))
	lockfile["config.json"] = buildx.SHA256Bytes(depBytes)

	// 签名服务密钥对: 私钥只存在于 keys/, 构建机目录里没有
	pub, priv, err := attest.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := attest.SavePrivateKey(filepath.Join(root, "keys", "signer.key"), priv); err != nil {
		return nil, err
	}
	if err := attest.SavePublicKey(filepath.Join(root, "keys", "signer.pub"), pub); err != nil {
		return nil, err
	}
	return &attacks.World{Root: root, Pub: pub, Lockfile: lockfile}, nil
}

func header(s string) {
	fmt.Printf("\n\033[1m=== %s ===\033[0m\n", s)
}

func runHonestPipeline(w *attacks.World) error {
	header("诚实的四级流水线 (构建机不持有签名密钥)")
	res, err := w.RunPipeline(nil, func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	})
	if err != nil {
		return err
	}

	header("客户安装前独立核验 (只信签名公钥 + lockfile)")
	if err := w.Verify(res.ArtifactPath, res.BundlePath, true, func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	}); err != nil {
		return fmt.Errorf("诚实构建未通过核验: %w", err)
	}
	fmt.Println("  → 核验通过, 可以安装")
	return nil
}

func runReproducibility(w *attacks.World) error {
	header("可复现性: 同一份源码, 隔时间构建两次")
	r1, err := w.RunPipeline(nil, nil)
	if err != nil {
		return err
	}
	time.Sleep(1100 * time.Millisecond) // 拉开构建时间
	r2, err := w.RunPipeline(nil, nil)
	if err != nil {
		return err
	}
	fmt.Printf("  第一次构建 sha256=%s…\n  第二次构建 sha256=%s…\n", r1.BinaryDigest[:12], r2.BinaryDigest[:12])
	if r1.BinaryDigest != r2.BinaryDigest {
		return fmt.Errorf("两次构建摘要不一致, 可复现性不成立")
	}
	fmt.Println("  ✔ 逐字节一致 —— 细微时间差异不会破坏可复现构建")
	return nil
}

func runAttacksWith(w *attacks.World) error {
	scenarios := []struct {
		name string
		fn   func(*attacks.World) (bool, string, error)
	}{
		{"场景1: 发布产物在传输中被掉包", attacks.SwapArtifact},
		{"场景2: 构建机被攻破 (掉包产物求签名 / 伪造证明)", attacks.CompromisedBuilder},
		{"场景3: 依赖被临时替换 (拉取前污染 / 编译前掉包)", attacks.SwapDependency},
		{"场景4: 证明链被拼接、旧链重放到新产物", attacks.BreakChain},
	}
	allDetected := true
	for _, s := range scenarios {
		header(s.name)
		detected, detail, err := s.fn(w)
		if err != nil {
			return err
		}
		if detected {
			fmt.Printf("  \033[32m✔ 被识破\033[0m\n  核验器报告: %s\n", wrap(detail))
		} else {
			allDetected = false
			fmt.Printf("  \033[31m✗ 未被识破: %s\033[0m\n", detail)
		}
	}
	header("结论")
	if allDetected {
		fmt.Println("  全部篡改场景均被识破 ✔")
	} else {
		return fmt.Errorf("存在未被识破的篡改场景")
	}
	return nil
}

func wrap(s string) string {
	return strings.ReplaceAll(s, "; ", "\n  ")

}

func runHonest(root string) error {
	w, err := setup(root)
	if err != nil {
		return err
	}
	return runHonestPipeline(w)
}

func runAttacks(root string) error {
	w, err := setup(root)
	if err != nil {
		return err
	}
	return runAttacksWith(w)
}

func runDemo(root string) error {
	w, err := setup(root)
	if err != nil {
		return err
	}
	if err := runHonestPipeline(w); err != nil {
		return err
	}
	if err := runReproducibility(w); err != nil {
		return err
	}
	return runAttacksWith(w)
}

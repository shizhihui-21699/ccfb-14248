// Package buildx 提供可复现构建所需的基础工具:
// 文件哈希、确定性 tar.gz 打包/解包、可复现的 go build。
package buildx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// SHA256Bytes 返回内容的 sha256 十六进制摘要。
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashFile 返回文件的 sha256 十六进制摘要。
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Entry 描述要打进 tar 的一个文件。
type Entry struct {
	Name string // tar 内的路径
	Path string // 磁盘上的源文件
}

// TarGzFiles 确定性地把若干文件打成 tar.gz:
// 条目按名称排序, mtime/uid/gid 全部置零, gzip 头不写时间戳。
func TarGzFiles(entries []Entry) ([]byte, error) {
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var buf bytes.Buffer
	gw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gw)
	for _, e := range sorted {
		data, err := os.ReadFile(e.Path)
		if err != nil {
			return nil, err
		}
		mode := int64(0o644)
		if strings.HasSuffix(e.Name, "app") || isExecutable(e.Path) {
			mode = 0o755
		}
		hdr := &tar.Header{
			Name:     e.Name,
			Mode:     mode,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			// ModTime/AccessTime/ChangeTime 零值 -> 可复现
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TarGzDir 确定性地把整个目录打成 tar.gz (路径按字典序)。
func TarGzDir(dir string) ([]byte, error) {
	var entries []Entry
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		entries = append(entries, Entry{Name: filepath.ToSlash(rel), Path: path})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return TarGzFiles(entries)
}

// UntarGz 解包 tar.gz 到目标目录, 拒绝路径穿越条目。
func UntarGz(data []byte, dest string) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("tar entry %q escapes destination", hdr.Name)
		}
		target := filepath.Join(dest, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}

// GoBuild 以可复现方式编译 srcDir 下的 Go 程序:
// -trimpath 去掉本机路径, -buildvcs=false 不嵌入 VCS 信息,
// -ldflags=-buildid= 去掉随机 build id, CGO 关闭避免本机 libc 差异。
func GoBuild(srcDir, outAbs string) error {
	outAbs, err := filepath.Abs(outAbs) // 输出路径先转绝对, 否则相对路径会相对 srcDir 解析
	if err != nil {
		return err
	}
	cmd := exec.Command("go", "build",
		"-trimpath",
		"-buildvcs=false",
		"-ldflags=-buildid=",
		"-o", outAbs, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOTOOLCHAIN=local", // 不联网换工具链
		"GOPROXY=off",       // 不联网拉依赖 (演示项目只用标准库)
		"GOFLAGS=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed in %s: %v\n%s", srcDir, err, out)
	}
	return nil
}

// GoVersion 返回本机 Go 工具链版本字符串。
func GoVersion() string {
	out, err := exec.Command("go", "version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// Copy 复制文件。
func Copy(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode())
}

// CopyDir 递归复制目录。
func CopyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return Copy(path, target)
	})
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&0o111 != 0
}

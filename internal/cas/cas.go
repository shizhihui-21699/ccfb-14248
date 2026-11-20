// Package cas 是一个极简的内容寻址存储 (content-addressed store):
// 按内容的 sha256 存取, 读取时校验完整性。构建机把源码快照和依赖放进 CAS,
// 签名服务按摘要取出来做独立重建 —— 摘要对不上立刻暴露。
package cas

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type Store struct {
	Dir string
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// Put 写入内容, 返回其 sha256 十六进制摘要。
func (s *Store) Put(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	path := filepath.Join(s.Dir, digest)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, path); err != nil {
			return "", err
		}
	}
	return digest, nil
}

// Get 按摘要读取, 并重新校验内容完整性。
func (s *Store) Get(digest string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, digest))
	if err != nil {
		return nil, fmt.Errorf("CAS object %s…: %w", short(digest), err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("CAS integrity failure: object %s… was corrupted", short(digest))
	}
	return b, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

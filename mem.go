package socks5

import (
	"context"
)

// mem allocation by ctinkong
type MemAllocation interface {
	Alloc(ctx context.Context, size int) []byte
	Free(ctx context.Context, bs []byte)
}

// mem mgr by ctinkong
type MemMgr interface {
	Create(ctx context.Context) MemAllocation
}

type Mem struct{}

func (m *Mem) Alloc(ctx context.Context, size int) []byte {
	return make([]byte, size)
}

func (m *Mem) Free(ctx context.Context, bs []byte) {

}

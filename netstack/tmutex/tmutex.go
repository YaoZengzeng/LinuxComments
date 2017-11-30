// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tmutex provides the implementation of a mutex that implements an
// efficient TryLock function in addition to Lock and Unlock.
// tmutex在Lock和Unlock的基础之上增加了TryLock函数
package tmutex

import (
	"sync/atomic"
)

// Mutex is a mutual exclusion primitive that implements TryLock in addition
// to Lock and Unlock.
type Mutex struct {
	v  int32
	ch chan struct{}
}

// Init initializes the mutex.
func (m *Mutex) Init() {
	// 初始化将m.v设置为1
	m.v = 1
	m.ch = make(chan struct{}, 1)
}

// Lock acquires the mutex. If it is currently held by another goroutine, Lock
// will wait until it has a chance to acquire it.
func (m *Mutex) Lock() {
	// Uncontended case.
	// 若对m.v减1，若得到0，则表示成功获取该锁
	if atomic.AddInt32(&m.v, -1) == 0 {
		return
	}

	// 若未能获取该锁
	for {
		// Try to acquire the mutex again, at the same time making sure
		// that m.v is negative, which indicates to the owner of the
		// lock that it is contended, which will force it to try to wake
		// someone up when it releases the mutex.
		// 获取的m.v的值，若m.v的值小于0，说明已经有waiter在等待了，直接往下执行即可
		// 若m.v >= 0，则将其置换为-1，如果置换出来的值为1，表示获得该锁，直接返还
		// 否则，只能说明是该锁第一个waiter，后续的锁，根本就没有置换m.v的机会
		// 当v为1时，可能有多个SwapInt32执行，但最终只有一个能够置换出1
		if v := atomic.LoadInt32(&m.v); v >= 0 && atomic.SwapInt32(&m.v, -1) == 1 {
			return
		}

		// Wait for the mutex to be released before trying again.
		// 等待Unlock执行结束，再次进行尝试
		<-m.ch
	}
}

// TryLock attempts to acquire the mutex without blocking. If the mutex is
// currently held by another goroutine, it fails to acquire it and returns
// false.
// TryLock在不阻塞的情况下对锁进行竞争，如果当前锁已经为另外的goroutine所有，则直接退出
// 否则尝试竞争该锁
func (m *Mutex) TryLock() bool {
	v := atomic.LoadInt32(&m.v)
	if v <= 0 {
		return false
	}
	// CompareAndSwapInt32(addr *int64, old, new int32)
	return atomic.CompareAndSwapInt32(&m.v, 1, 0)
}

// Unlock releases the mutex.
func (m *Mutex) Unlock() {
	// 如果当前置换出的m.v的值为0，则说明没有等待该锁的waiter，则直接返还
	if atomic.SwapInt32(&m.v, 1) == 0 {
		// There were no pending waiters.
		return
	}

	// Wake some waiter up.
	// 有等待该锁的waiter，则将其唤醒
	select {
	case m.ch <- struct{}{}:
	default:
	}
}

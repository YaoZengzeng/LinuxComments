// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tmutex

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBasicLock(t *testing.T) {
	var m Mutex
	m.Init()

	m.Lock()

	// Try blocking lock the mutex from a different goroutine. This must
	// not block because the mutex is held.
	ch := make(chan struct{}, 1)
	go func() {
		m.Lock()
		ch <- struct{}{}
		m.Unlock()
		ch <- struct{}{}
	}()

	select {
	// 若<-ch成功，则说明goroutine中的m.Lock()成功，重复Lock()，所以失败
	case <-ch:
		t.Fatalf("Lock succeeded on locked mutex")
	case <-time.After(100 * time.Millisecond):
	}

	// Unlock the mutex and make sure that the goroutine waiting on Lock()
	// unblocks and succeeds.
	m.Unlock()

	select {
	// 此时等待goroutine中Lock成功
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Lock failed to acquire unlocked mutex")
	}

	// Make sure we can lock and unlock again.
	// 保证我们还能Lock()和Unlock()
	m.Lock()
	m.Unlock()
}

func TestTryLock(t *testing.T) {
	var m Mutex
	m.Init()

	// Try to lock. It should succeed.
	if !m.TryLock() {
		t.Fatalf("TryLock failed on unlocked mutex")
	}

	// Try to lock again, it should now fail.
	if m.TryLock() {
		t.Fatalf("TryLock succeeded on locked mutex")
	}

	// Try blocking lock the mutex from a different goroutine. This must
	// not block because the mutex is held.
	ch := make(chan struct{}, 1)
	go func() {
		m.Lock()
		ch <- struct{}{}
		m.Unlock()
	}()

	select {
	case <-ch:
		t.Fatalf("Lock succeeded on locked mutex")
	case <-time.After(100 * time.Millisecond):
	}

	// Unlock the mutex and make sure that the goroutine waiting on Lock()
	// unblocks and succeeds.
	m.Unlock()

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Lock failed to acquire unlocked mutex")
	}
}

func TestMutualExclusion(t *testing.T) {
	var m Mutex
	m.Init()

	// Test mutual exclusion by running "gr" goroutines concurrently, and
	// have each one increment a counter "iters" times within the critical
	// section established by the mutex.
	//
	// If at the end the counter is not gr * iters, then we know that
	// goroutines ran concurrently within the critical section.
	//
	// If one of the goroutines doesn't complete, it's likely a bug that
	// causes to it to wait forever.
	// 生成gr个goroutine，每个对变量v都增加iters次
	const gr = 1000
	const iters = 100000
	v := 0
	var wg sync.WaitGroup
	for i := 0; i < gr; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < iters; j++ {
				m.Lock()
				v++
				m.Unlock()
			}
			wg.Done()
		}()
	}

	wg.Wait()

	if v != gr*iters {
		t.Fatalf("Bad count: got %v, want %v", v, gr*iters)
	}
}

func TestMutualExclusionWithTryLock(t *testing.T) {
	var m Mutex
	m.Init()

	// Similar to the previous, with the addition of some goroutines that
	// only increment the count if TryLock succeeds.
	// 和前一个例子基本相同，除了有的goroutine在TryLock成功的时候增加counter
	const gr = 1000
	const iters = 100000
	total := int64(gr * iters)
	v := int64(0)
	var wg sync.WaitGroup
	for i := 0; i < gr; i++ {
		wg.Add(2)
		go func() {
			for j := 0; j < iters; j++ {
				m.Lock()
				v++
				m.Unlock()
			}
			wg.Done()
		}()
		go func() {
			local := int64(0)
			for j := 0; j < iters; j++ {
				if m.TryLock() {
					v++
					m.Unlock()
					local++
				}
			}
			// local其实就是在iters次的遍历中，TryLock()成功的次数
			atomic.AddInt64(&total, local)
			wg.Done()
		}()
	}

	wg.Wait()

	if v != total {
		t.Fatalf("Bad count: got %v, want %v", v, total)
	}
}

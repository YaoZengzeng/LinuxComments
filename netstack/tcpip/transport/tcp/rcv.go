// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"container/heap"

	"github.com/google/netstack/tcpip/seqnum"
)

// receiver holds the state necessary to receive TCP segments and turn them
// into a stream of bytes.
type receiver struct {
	ep *endpoint

	rcvNxt seqnum.Value

	// rcvAcc is one beyond the last acceptable sequence number. That is,
	// the "largest" sequence value that the receiver has announced to the
	// its peer that it's willing to accept. This may be different than
	// rcvNxt + rcvWnd if the receive window is reduced; in that case we
	// have to reduce the window as we receive more data instead of
	// shrinking it.
	// rcvAcc是最后一个可接受的sequence number + 1，它可能在receive window减小的时候
	// 和rcvNext + rcvWnd不同
	rcvAcc seqnum.Value

	rcvWndScale uint8

	closed bool

	pendingRcvdSegments segmentHeap
	pendingBufUsed      seqnum.Size
	pendingBufSize      seqnum.Size
}

func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	return &receiver{
		ep:             ep,
		rcvNxt:         irs + 1,
		rcvAcc:         irs.Add(rcvWnd + 1),
		rcvWndScale:    rcvWndScale,
		pendingBufSize: rcvWnd,
	}
}

// acceptable checks if the segment sequence number range is acceptable
// according to the table on page 26 of RFC 793.
func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	rcvWnd := r.rcvNxt.Size(r.rcvAcc)
	if rcvWnd == 0 {
		// 当接受窗口的大小为零时，segment的大小为零且该segment就是要接收的下一个segment，返回true
		return segLen == 0 && segSeq == r.rcvNxt
	}

	// 如果seq在(r.rcvNxt, rcvWnd)构成的窗口内或者(r.rcvNxt, rcvWnd)和(segSeq, segLen)
	// 有交集则返回true
	return segSeq.InWindow(r.rcvNxt, rcvWnd) ||
		seqnum.Overlap(r.rcvNxt, rcvWnd, segSeq, segLen)
}

// getSendParams returns the parameters needed by the sender when building
// segments to send.
func (r *receiver) getSendParams() (rcvNxt seqnum.Value, rcvWnd seqnum.Size) {
	// Calculate the window size based on the current buffer size.
	n := r.ep.receiveBufferAvailable()
	acc := r.rcvNxt.Add(seqnum.Size(n))
	// r.rcvAcc只会递增而不会减小，因此即使窗口减小也不会让已经接收到的数据失效
	if r.rcvAcc.LessThan(acc) {
		r.rcvAcc = acc
	}

	// 而窗口大小是通过r.rcvAcc - r.rcvNxt获得的
	return r.rcvNxt, r.rcvNxt.Size(r.rcvAcc) >> r.rcvWndScale
}

// nonZeroWindow is called when the receive window grows from zero to nonzero;
// in such cases we may need to send an ack to indicate to our peer that it can
// resume sending data.
func (r *receiver) nonZeroWindow() {
	if (r.rcvAcc-r.rcvNxt)>>r.rcvWndScale != 0 {
		// We never got around to announcing a zero window size, so we
		// don't need to immediately announce a nonzero one.
		return
	}

	// Immediately send an ack.
	r.ep.snd.sendAck()
}

// consumeSegment attemps to consume a segment that was received by r. The
// segment may have just been received or may have been received earlier but
// wasn't ready to be consumed then.
// consumeSegment用于消费由r接收到的segment，该segment可能是刚刚接收的，也可能是之前接收
// 但是还没有准备好被接收的
//
// Returns true if the segment was consumed, false if it cannot be consumed
// yet because of a missing segment.
// 如果segment能够被消费，则返回true，否则返回false，因为中间有遗漏的segment
func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {
	if segLen > 0 {
		// If the segment doesn't include the seqnum we're expecting to
		// consume now, we're missing a segment. We cannot proceed until
		// we receive that segment though.
		// 如果该segment不包含我们想要消费的segment，则丢弃它
		if !r.rcvNxt.InWindow(segSeq, segLen) {
			return false
		}

		// Trim segment to eliminate already acknowledged data.
		// 截断之前已经ACK的数据
		if segSeq.LessThan(r.rcvNxt) {
			diff := segSeq.Size(r.rcvNxt)
			segLen -= diff
			segSeq.UpdateForward(diff)
			s.sequenceNumber.UpdateForward(diff)
			s.data.TrimFront(int(diff))
		}

		// Move segment to ready-to-deliver list. Wakeup any waiters.
		// 将segment移动到接收队列中，并且唤醒waiters
		r.ep.readyToRead(s)

	} else if segSeq != r.rcvNxt {
		return false
	}

	// Update the segment that we're expecting to consume.
	// 更新我们希望接收到的sequence number
	r.rcvNxt = segSeq.Add(segLen)
	// 当收到的为Fin包时
	if s.flagIsSet(flagFin) {
		r.rcvNxt++

		// Send ACK immediately.
		r.ep.snd.sendAck()

		// Tell any readers that no more data will come.
		r.closed = true
		r.ep.readyToRead(nil)

		// Flush out any pending segments, except the very first one if
		// it happens to be the one we're handling now because the
		// caller is using it.
		first := 0
		if len(r.pendingRcvdSegments) != 0 && r.pendingRcvdSegments[0] == s {
			first = 1
		}

		for i := first; i < len(r.pendingRcvdSegments); i++ {
			r.pendingRcvdSegments[i].decRef()
		}
		r.pendingRcvdSegments = r.pendingRcvdSegments[:first]
	}

	return true
}

// handleRcvdSegment handles TCP segments directed at the connection managed by
// r as they arrive. It is called by the protocol main loop.
func (r *receiver) handleRcvdSegment(s *segment) {
	// We don't care about receive processing anymore if the receive side
	// is closed.
	if r.closed {
		return
	}

	segLen := seqnum.Size(s.data.Size())
	segSeq := s.sequenceNumber

	// If the sequence number range is outside the acceptable range, just
	// send an ACK. This is according to RFC 793, page 37.
	// 如果接收到的sequence number超出了可以接受的范围，则直接发送一个ACK
	if !r.acceptable(segSeq, segLen) {
		r.ep.snd.sendAck()
		return
	}

	// Defer segment processing if it can't be consumed now.
	// 如果segment不能现在被消费，则推迟对它的处理
	if !r.consumeSegment(s, segSeq, segLen) {
		if segLen > 0 || s.flagIsSet(flagFin) {
			// We only store the segment if it's within our buffer
			// size limit.
			// 如果pendingBuf还有空间可用，则将其加入pendingRcvdSegments
			if r.pendingBufUsed < r.pendingBufSize {
				r.pendingBufUsed += s.logicalLen()
				s.incRef()
				heap.Push(&r.pendingRcvdSegments, s)
			}

			// Immediately send an ack so that the peer knows it may
			// have to retransmit.
			// 立即返回ACK，好让对端知道也许可以进行重传了
			r.ep.snd.sendAck()
		}
		return
	}

	// By consuming the current segment, we may have filled a gap in the
	// sequence number domain that allows pending segments to be consumed
	// now. So try to do it.
	// 通过消耗current segment，我们可能已经填补了sequence number之间的gap，因此
	// 可以尝试发送pending segment
	for !r.closed && r.pendingRcvdSegments.Len() > 0 {
		s := r.pendingRcvdSegments[0]
		segLen := seqnum.Size(s.data.Size())
		segSeq := s.sequenceNumber

		// Skip segment altogether if it has already been acknowledged.
		if !segSeq.Add(segLen-1).LessThan(r.rcvNxt) &&
			!r.consumeSegment(s, segSeq, segLen) {
			break
		}

		heap.Pop(&r.pendingRcvdSegments)
		r.pendingBufUsed -= s.logicalLen()
		s.decRef()
	}
}

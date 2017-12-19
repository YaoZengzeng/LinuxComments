// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"sync/atomic"

	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
)

// Flags that may be set in a TCP segment.
const (
	flagFin = 1 << iota
	flagSyn
	flagRst
	flagPsh
	flagAck
	flagUrg
)

// segment represents a TCP segment. It holds the payload and parsed TCP segment
// information, and can be added to intrusive lists.
// segment is mostly immutable, the only field allowed to change is viewToDeliver.
// segment 代表了一个TCP segment，其中包含了负载以及经过分析的TCP segment信息，并且能够被加入到
// intrusive list中，segment基本上是一成不变的，唯一可以被改变的字段就是viewToDeliver
type segment struct {
	segmentEntry
	refCnt int32
	id     stack.TransportEndpointID
	route  stack.Route
	data   buffer.VectorisedView
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views [8]buffer.View
	// viewToDeliver keeps track of the next View that should be
	// delivered by the Read endpoint.
	// viewToDeliver代表下一个将传输给Read endpoint的View
	viewToDeliver  int
	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          uint8
	window         seqnum.Size

	// parsedOptions stores the parsed values from the options in the segment.
	parsedOptions header.TCPOptions
	options       []byte
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, vv *buffer.VectorisedView) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.data = vv.Clone(s.views[:])
	return s
}

func newSegmentFromView(r *stack.Route, id stack.TransportEndpointID, v buffer.View) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.views[0] = v
	s.data = buffer.NewVectorisedView(len(v), s.views[:1])
	return s
}

func (s *segment) clone() *segment {
	t := &segment{
		refCnt:         1,
		id:             s.id,
		sequenceNumber: s.sequenceNumber,
		ackNumber:      s.ackNumber,
		flags:          s.flags,
		window:         s.window,
		route:          s.route.Clone(),
		viewToDeliver:  s.viewToDeliver,
	}
	t.data = s.data.Clone(t.views[:])
	return t
}

func (s *segment) flagIsSet(flag uint8) bool {
	return (s.flags & flag) != 0
}

func (s *segment) decRef() {
	if atomic.AddInt32(&s.refCnt, -1) == 0 {
		s.route.Release()
	}
}

func (s *segment) incRef() {
	atomic.AddInt32(&s.refCnt, 1)
}

// logicalLen is the segment length in the sequence number space. It's defined
// as the data length plus one for each of the SYN and FIN bits set.
// logicalLen是在sequence number space空间中的segment length，即data length加上一个
// SYN或者FIN的长度
func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(s.data.Size())
	if s.flagIsSet(flagSyn) {
		l++
	}
	if s.flagIsSet(flagFin) {
		l++
	}
	return l
}

// parse populates the sequence & ack numbers, flags, and window fields of the
// segment from the TCP header stored in the data. It then updates the view to
// skip the data. Returns boolean indicating if the parsing was successful.
// parse从tcp header中解析出sequence以及ack numbers，flags，以及window，跳过data，更新view
func (s *segment) parse() bool {
	h := header.TCP(s.data.First())

	// h is the header followed by the payload. We check that the offset to
	// the data respects the following constraints:
	// 1. That it's at least the minimum header size; if we don't do this
	//    then part of the header would be delivered to user.
	// 2. That the header fits within the buffer; if we don't do this, we
	//    would panic when we tried to access data beyond the buffer.
	//
	// N.B. The segment has already been validated as having at least the
	//      minimum TCP size before reaching here, so it's safe to read the
	//      fields.
	offset := int(h.DataOffset())
	if offset < header.TCPMinimumSize || offset > len(h) {
		return false
	}

	s.options = []byte(h[header.TCPMinimumSize:offset])
	s.parsedOptions = header.ParseTCPOptions(s.options)
	s.data.TrimFront(offset)

	s.sequenceNumber = seqnum.Value(h.SequenceNumber())
	s.ackNumber = seqnum.Value(h.AckNumber())
	s.flags = h.Flags()
	s.window = seqnum.Size(h.WindowSize())

	return true
}

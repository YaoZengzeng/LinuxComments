// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/waiter"
)

// PingProtocolName is a pseudo transport protocol used to handle ping replies.
// Use it when constructing a stack that intends to use ipv4.Ping.
const PingProtocolName = "icmpv4ping"

// pingProtocolNumber is a fake transport protocol used to
// deliver incoming ICMP echo replies. The ICMP identifier
// number is used as a port number for multiplexing.
const pingProtocolNumber tcpip.TransportProtocolNumber = 256 + 11

func (e *endpoint) handleICMP(r *stack.Route, vv *buffer.VectorisedView) {
	v := vv.First()
	if len(v) < header.ICMPv4MinimumSize {
		return
	}
	h := header.ICMPv4(v)

	switch h.Type() {
	case header.ICMPv4Echo:
		if len(v) < header.ICMPv4EchoMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv4MinimumSize)
		// 创建一个echoRequest的实例
		req := echoRequest{r: r.Clone(), v: vv.ToView()}
		select {
		// 将echoRequest实例通过管道e.echoRequests进行发送
		case e.echoRequests <- req:
		default:
			req.r.Release()
		}
	case header.ICMPv4EchoReply:
		e.dispatcher.DeliverTransportPacket(r, pingProtocolNumber, vv)
	}
	// TODO(crawshaw): Handle other ICMP types.
}

type echoRequest struct {
	r stack.Route
	v buffer.View
}

func (e *endpoint) echoReplier() {
	for req := range e.echoRequests {
		sendICMPv4(&req.r, header.ICMPv4EchoReply, 0, req.v)
		req.r.Release()
	}
}

func sendICMPv4(r *stack.Route, typ header.ICMPv4Type, code byte, data buffer.View) *tcpip.Error {
	hdr := buffer.NewPrependable(header.ICMPv4MinimumSize + int(r.MaxHeaderLength()))

	icmpv4 := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	icmpv4.SetType(typ)
	icmpv4.SetCode(code)
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))

	return r.WritePacket(&hdr, data, header.ICMPv4ProtocolNumber)
}

// A Pinger can send echo requests to an address.
type Pinger struct {
	Stack     *stack.Stack
	NICID     tcpip.NICID
	Addr      tcpip.Address
	LocalAddr tcpip.Address // optional
	Wait      time.Duration // if zero, defaults to 1 second
	Count     uint16        // if zero, defaults to MaxUint16
}

// Ping sends echo requests to an ICMPv4 endpoint.
// Responses are streamed to the channel ch.
// Ping会向一个ICMPv4 endpoint发送请求，并且回复将缓存在channel ch中
func (p *Pinger) Ping(ctx context.Context, ch chan<- PingReply) *tcpip.Error {
	count := p.Count
	if count == 0 {
		count = 1<<16 - 1
	}
	wait := p.Wait
	if wait == 0 {
		wait = 1 * time.Second
	}

	// 寻找路由
	r, err := p.Stack.FindRoute(p.NICID, p.LocalAddr, p.Addr, ProtocolNumber)
	if err != nil {
		return err
	}

	netProtos := []tcpip.NetworkProtocolNumber{ProtocolNumber}
	ep := &pingEndpoint{
		stack: p.Stack,
		pktCh: make(chan buffer.View, 1),
	}
	id := stack.TransportEndpointID{
		LocalAddress:  r.LocalAddress,
		RemoteAddress: p.Addr,
	}

	_, err = p.Stack.PickEphemeralPort(func(port uint16) (bool, *tcpip.Error) {
		id.LocalPort = port
		err := p.Stack.RegisterTransportEndpoint(p.NICID, netProtos, pingProtocolNumber, id, ep)
		switch err {
		case nil:
			return true, nil
		case tcpip.ErrPortInUse:
			// 如果端口已经被占用，则再选一个
			return false, nil
		default:
			return false, err
		}
	})
	if err != nil {
		return err
	}
	// 注册一个临时的TransportEndpoint
	defer p.Stack.UnregisterTransportEndpoint(p.NICID, netProtos, pingProtocolNumber, id)

	v := buffer.NewView(4)
	// 将LocalPort作为identifier写入
	binary.BigEndian.PutUint16(v[0:], id.LocalPort)

	start := time.Now()

	done := make(chan struct{})
	// 另外启动一个goroutine，从pingEndpoint中读取count个封包，从中获取序号seq
	go func(count int) {
	loop:
		for ; count > 0; count-- {
			select {
			case v := <-ep.pktCh:
				// 获取seq
				seq := binary.BigEndian.Uint16(v[header.ICMPv4MinimumSize+2:])
				ch <- PingReply{
					Duration:  time.Since(start) - time.Duration(seq)*wait,
					SeqNumber: seq,
				}
			case <-ctx.Done():
				break loop
			}
		}
		close(done)
	}(int(count))
	// 匿名函数结束，本函数才能结束
	defer func() { <-done }()

	t := time.NewTicker(wait)
	defer t.Stop()
	// 发送count个ping request
	for seq := uint16(0); seq < count; seq++ {
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil
		}
		// 写入seq
		binary.BigEndian.PutUint16(v[2:], seq)
		sent := time.Now()
		// 其中v为负载，icmp头部在sendICMPv4中构建
		if err := sendICMPv4(&r, header.ICMPv4Echo, 0, v); err != nil {
			ch <- PingReply{
				Error:     err,
				Duration:  time.Since(sent),
				SeqNumber: seq,
			}
		}
	}
	return nil
}

// PingReply summarizes an ICMP echo reply.
type PingReply struct {
	Error     *tcpip.Error // reports any errors sending a ping request
	Duration  time.Duration
	SeqNumber uint16
}

type pingProtocol struct{}

func (*pingProtocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return nil, tcpip.ErrNotSupported // endpoints are created directly
}

func (*pingProtocol) Number() tcpip.TransportProtocolNumber { return pingProtocolNumber }

func (*pingProtocol) MinimumPacketSize() int { return header.ICMPv4EchoMinimumSize }

func (*pingProtocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	ident := binary.BigEndian.Uint16(v[4:])
	return 0, ident, nil
}

func (*pingProtocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, *buffer.VectorisedView) bool {
	return true
}

// SetOption implements TransportProtocol.SetOption.
func (p *pingProtocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

func init() {
	stack.RegisterTransportProtocolFactory(PingProtocolName, func() stack.TransportProtocol {
		return &pingProtocol{}
	})
}

type pingEndpoint struct {
	stack *stack.Stack
	pktCh chan buffer.View
}

func (e *pingEndpoint) Close() {
	close(e.pktCh)
}

// pingEndpoint的处理方式就是将VectorisedView转换为View并发送给channel e.pktCh
func (e *pingEndpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv *buffer.VectorisedView) {
	select {
	case e.pktCh <- vv.ToView():
	default:
	}
}

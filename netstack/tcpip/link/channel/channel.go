// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package channel provides the implemention of channel-based data-link layer
// endpoints. Such endpoints allow injection of inbound packets and store
// outbound packets in a channel.
// channel类型的endpoint允许包的注入以及将外出的包存入channel
package channel

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/stack"
)

// PacketInfo holds all the information about an outbound packet.
// PacketInfo包含了发出的包的头部，负载以及网络层协议号
type PacketInfo struct {
	Header  buffer.View
	Payload buffer.View
	Proto   tcpip.NetworkProtocolNumber
}

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
// channel类型的endpoint，将发出的包储存在channel中，并允许包注入
type Endpoint struct {
	// 网络层的dispatcher
	dispatcher stack.NetworkDispatcher
	mtu        uint32
	linkAddr   tcpip.LinkAddress

	// C is where outbound packets are queued.
	// 发出的包都存在C中
	C chan PacketInfo
}

// New creates a new channel endpoint.
func New(size int, mtu uint32, linkAddr tcpip.LinkAddress) (tcpip.LinkEndpointID, *Endpoint) {
	e := &Endpoint{
		C:        make(chan PacketInfo, size),
		mtu:      mtu,
		linkAddr: linkAddr,
	}

	return stack.RegisterLinkEndpoint(e), e
}

// Drain removes all outbound packets from the channel and counts them.
func (e *Endpoint) Drain() int {
	c := 0
	for {
		select {
		case <-e.C:
			c++
		default:
			return c
		}
	}
}

// Inject injects an inbound packet.
func (e *Endpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	// 克隆封包，作为输入封包
	uu := vv.Clone(nil)
	e.dispatcher.DeliverNetworkPacket(e, "", protocol, &uu)
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePacket stores outbound packets into the channel.
func (e *Endpoint) WritePacket(_ *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	p := PacketInfo{
		Header: hdr.View(),
		Proto:  protocol,
	}

	if payload != nil {
		p.Payload = make(buffer.View, len(payload))
		copy(p.Payload, payload)
	}

	select {
	case e.C <- p:
	default:
	}

	return nil
}

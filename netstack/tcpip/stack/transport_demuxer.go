// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"sync"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
)

type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

// transportEndpoints manages all endpoints of a given protocol. It has its own
// mutex so as to reduce interference between protocols.
// transportEndpoints管理给定protocol的所有endpoints
type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint
}

// transportDemuxer demultiplexes packets targeted at a transport endpoint
// (i.e., after they've been parsed by the network layer). It does two levels
// of demultiplexing: first based on the network and transport protocols, then
// based on endpoints IDs.
// 多路分解，分两步进行，首先根据network和transport protocol进行分发，再根据endpoints ID进行分发
type transportDemuxer struct {
	protocol map[protocolIDs]*transportEndpoints
}

func newTransportDemuxer(stack *Stack) *transportDemuxer {
	d := &transportDemuxer{protocol: make(map[protocolIDs]*transportEndpoints)}

	// Add each network and and transport pair to the demuxer.
	for netProto := range stack.networkProtocols {
		for proto := range stack.transportProtocols {
			// 将networkProtocols和transportProtocols两两匹配
			d.protocol[protocolIDs{netProto, proto}] = &transportEndpoints{endpoints: make(map[TransportEndpointID]TransportEndpoint)}
		}
	}

	return d
}

// registerEndpoint registers the given endpoint with the dispatcher such that
// packets that match the endpoint ID are delivered to it.
func (d *transportDemuxer) registerEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	// 遍历netProtos
	for i, n := range netProtos {
		if err := d.singleRegisterEndpoint(n, protocol, id, ep); err != nil {
			d.unregisterEndpoint(netProtos[:i], protocol, id)
			return err
		}
	}

	return nil
}

func (d *transportDemuxer) singleRegisterEndpoint(netProto tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	// 利用netProto和protocol组合查找，获取对应的eps
	eps, ok := d.protocol[protocolIDs{netProto, protocol}]
	if !ok {
		return nil
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	// 再检测TransportEndpointID是否已经存在
	if _, ok := eps.endpoints[id]; ok {
		return tcpip.ErrPortInUse
	}

	// 注册TransportEndpoint
	eps.endpoints[id] = ep

	return nil
}

// unregisterEndpoint unregisters the endpoint with the given id such that it
// won't receive any more packets.
func (d *transportDemuxer) unregisterEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {
	for _, n := range netProtos {
		if eps, ok := d.protocol[protocolIDs{n, protocol}]; ok {
			eps.mu.Lock()
			delete(eps.endpoints, id)
			eps.mu.Unlock()
		}
	}
}

// deliverPacket attempts to deliver the given packet. Returns true if it found
// an endpoint, false otherwise.
func (d *transportDemuxer) deliverPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv *buffer.VectorisedView, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocolIDs{r.NetProto, protocol}]
	if !ok {
		return false
	}

	eps.mu.RLock()
	b := d.deliverPacketLocked(r, eps, vv, id)
	eps.mu.RUnlock()

	return b
}

func (d *transportDemuxer) deliverPacketLocked(r *Route, eps *transportEndpoints, vv *buffer.VectorisedView, id TransportEndpointID) bool {
	// Try to find a match with the id as provided.
	// 完全匹配
	if ep := eps.endpoints[id]; ep != nil {
		ep.HandlePacket(r, id, vv)
		return true
	}

	// Try to find a match with the id minus the local address.
	nid := id

	// 除了LocalAddress外，完全匹配
	nid.LocalAddress = ""
	if ep := eps.endpoints[nid]; ep != nil {
		ep.HandlePacket(r, id, vv)
		return true
	}

	// Try to find a match with the id minus the remote part.
	// 除了RemoteAddress和RemotePort外都匹配
	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = ""
	nid.RemotePort = 0
	if ep := eps.endpoints[nid]; ep != nil {
		ep.HandlePacket(r, id, vv)
		return true
	}

	// Try to find a match with only the local port.
	// 只有local port匹配
	nid.LocalAddress = ""
	if ep := eps.endpoints[nid]; ep != nil {
		ep.HandlePacket(r, id, vv)
		return true
	}

	return false
}

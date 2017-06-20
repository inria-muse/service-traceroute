package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type Receiver struct {
	PktChan       chan InputPkt
	LocalV4       net.IP
	LocalV6       net.IP
	SendStartChan chan bool
	HasSentSend   bool
	Curr          CurrStatus
	OutChan       chan string
	FlowOutChan   chan CurrStatus
	FlowInChan    chan CurrStatus
	ProbeOutChan  chan CurrStatus
	ProbeInChan   chan CurrStatus
}

type CurrStatus struct {
	Ts          int64
	LocalHw     net.HardwareAddr
	RemHw       net.HardwareAddr
	LocalIp     net.IP
	RemIp       net.IP
	TCPLocalIp  net.IP
	TCPRemIp    net.IP
	IpId        uint16
	IpTtl       uint8
	LocalPort   layers.TCPPort
	RemPort     layers.TCPPort
	Seq         uint32
	Ack         uint32
	TcpHLen     uint32
	Ip4         *layers.IPv4
	Ip6         *layers.IPv6
	Dir         int
	IpDataLen   uint32
	Transport   layers.IPProtocol
	IcmpPayload []byte
}

const (
	In  = 0
	Out = 1
)

func (r *Receiver) NewReceiver(pktChan chan InputPkt, hostV4 net.IP, hostV6 net.IP, outChan chan string) {
	r.PktChan = pktChan
	r.LocalV4 = hostV4
	r.LocalV6 = hostV6
	r.SendStartChan = make(chan bool, 2)

	r.Curr = CurrStatus{}
	r.OutChan = outChan

	r.FlowOutChan = make(chan CurrStatus, 100000)
	r.FlowInChan = make(chan CurrStatus, 100000)
	r.ProbeOutChan = make(chan CurrStatus, 100000)
	r.ProbeInChan = make(chan CurrStatus, 100000)
}

func (r *Receiver) GetHardwareAddresses(pkt InputPkt) {
	ethLayer := pkt.Packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	r.Curr.LocalHw = eth.SrcMAC
	r.Curr.RemHw = eth.DstMAC
}

func (r *Receiver) ParseTcpIn(pkt InputPkt, tcp *layers.TCP) {
	if tcp.SYN == true {
		r.Curr.Ack++
	}
	var c CurrStatus = r.Curr
	r.FlowInChan <- c
}

func (r *Receiver) IsProbePacket(pkt InputPkt, tcp *layers.TCP) bool {
	if r.Curr.Ip4 != nil {
		if r.Curr.Ip4.TTL <= 32 {
			return true
		}
	}
	// TODO IP6
	return false
}

func (r *Receiver) ParseTcpOut(pkt InputPkt, tcp *layers.TCP) {
	if r.IsProbePacket(pkt, tcp) {
		var c CurrStatus = r.Curr
		r.ProbeOutChan <- c
		return
	}

	if len(tcp.Payload) == 0 {
		return
	}

	if tcp.SYN == true {
		r.Curr.Seq++
	}
	if r.HasSentSend == false && tcp.SYN == false {
		r.GetHardwareAddresses(pkt)
		r.Curr.TCPLocalIp = r.Curr.LocalIp
		r.Curr.TCPRemIp = r.Curr.RemIp
		r.Curr.LocalPort = tcp.SrcPort
		r.Curr.RemPort = tcp.DstPort

		r.SendStartChan <- true
		r.HasSentSend = true
	}
	var c CurrStatus = r.Curr
	r.FlowOutChan <- c
}

func (r *Receiver) ParseTcpLayer(pkt InputPkt) error {
	tcpLayer := pkt.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return errors.New("not a TCP pkt")
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	r.Curr.Seq = tcp.Seq
	r.Curr.Ack = tcp.Ack
	r.Curr.TcpHLen = uint32(tcp.DataOffset * 4)
	if r.Curr.Dir == In {
		r.ParseTcpIn(pkt, tcp)
	} else {
		r.ParseTcpOut(pkt, tcp)
	}
	return nil
}

func (r *Receiver) ParseIcmpLayer(pkt InputPkt) error {
	if r.Curr.Dir == Out {
		return errors.New("Outgoing ICMP")
	}
	if icmp4Layer := pkt.Packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp, _ := icmp4Layer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
			var c CurrStatus = r.Curr
			c.IcmpPayload = make([]byte, len(icmp.LayerPayload()))
			copy(c.IcmpPayload, icmp.LayerPayload())
			r.ProbeInChan <- c
		}
	}
	//TODO: ICMPv6
	return nil
}

func (r *Receiver) ParseIpLayer(pkt InputPkt) error {
	if ip4Layer := pkt.Packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		r.Curr.Ip4 = ip4Layer.(*layers.IPv4)
		r.Curr.Ip6 = nil
		r.Curr.IpDataLen = uint32(r.Curr.Ip4.Length - 4*uint16(r.Curr.Ip4.IHL))
		r.Curr.IpId = r.Curr.Ip4.Id
		r.Curr.IpTtl = r.Curr.Ip4.TTL
		if r.Curr.Ip4.DstIP.String() == r.LocalV4.String() {
			r.Curr.Dir = In
			r.Curr.LocalIp = r.Curr.Ip4.DstIP
			r.Curr.RemIp = r.Curr.Ip4.SrcIP
		} else {
			r.Curr.Dir = Out
			r.Curr.LocalIp = r.Curr.Ip4.SrcIP
			r.Curr.RemIp = r.Curr.Ip4.DstIP
		}
		r.Curr.Transport = r.Curr.Ip4.Protocol
	} else if ip6Layer := pkt.Packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		r.Curr.Ip6 = ip6Layer.(*layers.IPv6)
		r.Curr.Ip4 = nil
		r.Curr.IpDataLen = uint32(r.Curr.Ip6.Length)
		r.Curr.IpTtl = r.Curr.Ip6.HopLimit // TODO Check if this does the job of v4 TTL
		if r.Curr.Ip6.DstIP.String() == r.LocalV6.String() {
			r.Curr.Dir = In
			r.Curr.LocalIp = r.Curr.Ip6.DstIP
			r.Curr.RemIp = r.Curr.Ip6.SrcIP
		} else {
			r.Curr.Dir = Out
			r.Curr.LocalIp = r.Curr.Ip6.SrcIP
			r.Curr.RemIp = r.Curr.Ip6.DstIP
		}
		r.Curr.Transport = r.Curr.Ip6.NextHeader

	} else {
		return errors.New("Not IP")
	}
	return nil
}

func (r *Receiver) Run() {
	r.OutChan <- fmt.Sprintf("%.3f: Starting receiver", float64(time.Now().UnixNano())/float64(time.Millisecond))
	for {
		pkt := <-r.PktChan
		r.Curr.Ts = pkt.Packet.Metadata().Timestamp.UnixNano()
		err := r.ParseIpLayer(pkt)
		if err != nil {
			continue
		}
		switch {
		case r.Curr.Transport == layers.IPProtocolTCP:
			r.ParseTcpLayer(pkt)
		case r.Curr.Transport == layers.IPProtocolICMPv4 || r.Curr.Transport == layers.IPProtocolICMPv6:
			r.ParseIcmpLayer(pkt)
		}
	}
}

package main

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"
)

type Receiver struct {
	PktChan              chan *gopacket.Packet
	LocalV4              net.IP
	LocalV6              net.IP
	SendStartChan        chan bool
	HasSentSend          bool
	StartWithEmptyPacket bool
	Curr                 CurrStatus
	OutChan              chan string
	FlowOutChan          chan CurrStatus
	FlowInChan           chan CurrStatus
	ProbeOutChan         chan CurrStatus
	ProbeInChan          chan CurrStatus

	StopChan chan bool
	DoneChan chan bool
}

type CurrStatus struct {
	Ts         int64
	LocalHw    net.HardwareAddr
	RemHw      net.HardwareAddr
	LocalIp    net.IP
	RemIp      net.IP
	TCPLocalIp net.IP
	TCPRemIp   net.IP
	IpId       uint16
	IpIdIcmp   uint16
	IpTtl      uint8
	LocalPort  layers.TCPPort
	RemPort    layers.TCPPort
	Seq        uint32
	Ack        uint32
	TcpHLen    uint32
	IPv4       bool
	IPv6       bool
	Dir        int
	IpDataLen  uint32
	Transport  layers.IPProtocol
}

const (
	In  = 0
	Out = 1
)

func (r *Receiver) NewReceiver(pktChan chan *gopacket.Packet, startWithEmptyPacket bool, hostV4 net.IP, hostV6 net.IP, outChan chan string) {
	r.PktChan = pktChan
	r.LocalV4 = hostV4
	r.LocalV6 = hostV6
	r.SendStartChan = make(chan bool, 2)

	r.StartWithEmptyPacket = startWithEmptyPacket

	r.Curr = CurrStatus{}
	r.OutChan = outChan

	r.FlowOutChan = make(chan CurrStatus, 100)
	r.FlowInChan = make(chan CurrStatus, 100)
	r.ProbeOutChan = make(chan CurrStatus, 100)
	r.ProbeInChan = make(chan CurrStatus, 100)

	r.StopChan = make(chan bool)
	r.DoneChan = make(chan bool)
}

func (r *Receiver) GetHardwareAddresses(pkt *gopacket.Packet) {
	ethLayer := (*pkt).Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	r.Curr.LocalHw = eth.SrcMAC
	r.Curr.RemHw = eth.DstMAC
}

func (r *Receiver) ParseTcpIn(pkt *gopacket.Packet, tcp *layers.TCP) {
	if tcp.SYN == true {
		r.Curr.Ack++
	}
	var c CurrStatus = r.Curr
	r.FlowInChan <- c
}

func (r *Receiver) IsProbePacket(pkt *gopacket.Packet, tcp *layers.TCP) bool {
	if r.Curr.IPv4 {
		if r.Curr.IpTtl <= 32 {
			return true
		}
	}
	// TODO IP6
	return false
}

func (r *Receiver) ParseTcpOut(pkt *gopacket.Packet, tcp *layers.TCP) {
	if r.IsProbePacket(pkt, tcp) {
		var c CurrStatus = r.Curr
		r.ProbeOutChan <- c
		return
	}

	r.Curr.Seq = tcp.Seq
	r.Curr.Ack = tcp.Ack

	if !r.StartWithEmptyPacket && len(tcp.Payload) == 0 {
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

func (r *Receiver) ParseTcpLayer(pkt *gopacket.Packet) error {
	tcpLayer := (*pkt).Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return errors.New("not a TCP pkt")
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	//May cause problems when parsing probes
	//r.Curr.Seq = tcp.Seq
	//r.Curr.Ack = tcp.Ack
	r.Curr.TcpHLen = uint32(tcp.DataOffset * 4)
	if r.Curr.Dir == In {
		r.ParseTcpIn(pkt, tcp)
	} else {
		r.ParseTcpOut(pkt, tcp)
	}
	return nil
}

func (r *Receiver) ParseIcmpLayer(pkt *gopacket.Packet) error {
	if r.Curr.Dir == Out {
		return errors.New("Outgoing ICMP")
	}
	if icmp4Layer := (*pkt).Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp, _ := icmp4Layer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
			var c CurrStatus = r.Curr
			c.IpIdIcmp = binary.BigEndian.Uint16(icmp.LayerPayload()[4:6])
			// c.IcmpPayload = make([]byte, len(icmp.LayerPayload()))
			// copy(c.IcmpPayload, icmp.LayerPayload())
			r.ProbeInChan <- c
		}
	}
	//TODO: ICMPv6
	return nil
}

func (r *Receiver) ParseIpLayer(pkt *gopacket.Packet) error {
	if ip4Layer := (*pkt).Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip := ip4Layer.(*layers.IPv4)
		r.Curr.IPv4 = true
		r.Curr.IPv6 = false
		r.Curr.IpDataLen = uint32(ip.Length - 4*uint16(ip.IHL))
		r.Curr.IpId = ip.Id
		r.Curr.IpTtl = ip.TTL
		if ip.DstIP.String() == r.LocalV4.String() {
			r.Curr.Dir = In
			r.Curr.LocalIp = ip.DstIP
			r.Curr.RemIp = ip.SrcIP
		} else {
			r.Curr.Dir = Out
			r.Curr.LocalIp = ip.SrcIP
			r.Curr.RemIp = ip.DstIP
		}
		r.Curr.Transport = ip.Protocol
	} else if ip6Layer := (*pkt).Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip := ip6Layer.(*layers.IPv6)
		r.Curr.IPv4 = false
		r.Curr.IPv6 = true
		r.Curr.IpDataLen = uint32(ip.Length)
		r.Curr.IpTtl = ip.HopLimit // TODO Check if this does the job of v4 TTL
		if ip.DstIP.String() == r.LocalV6.String() {
			r.Curr.Dir = In
			r.Curr.LocalIp = ip.DstIP
			r.Curr.RemIp = ip.SrcIP
		} else {
			r.Curr.Dir = Out
			r.Curr.LocalIp = ip.SrcIP
			r.Curr.RemIp = ip.DstIP
		}
		r.Curr.Transport = ip.NextHeader

	} else {
		return errors.New("Not IP")
	}
	return nil
}

func (r *Receiver) Run() {
	defer func() {
		r.DoneChan <- true
	}()
	for {
		select {
		case pkt := <-r.PktChan:
			r.Curr.Ts = (*pkt).Metadata().Timestamp.UnixNano()
			err := r.ParseIpLayer(pkt)
			if err != nil {
				continue
			}
			switch {
			case r.Curr.Transport == layers.IPProtocolTCP:
				err := r.ParseTcpLayer(pkt)
				if err != nil {
					//Error during parsing
				}

			case r.Curr.Transport == layers.IPProtocolICMPv4 || r.Curr.Transport == layers.IPProtocolICMPv6:
				err := r.ParseIcmpLayer(pkt)
				if err != nil {
					//Error during parsing
				}
			}
		case <-r.StopChan:
			return
		}
	}
}

func (r *Receiver) Stop() {
	r.StopChan <- true
}

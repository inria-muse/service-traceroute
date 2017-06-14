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
}

type CurrStatus struct {
	LocalIp      net.IP
	RemIp        net.IP
	LocalHw      net.HardwareAddr
	RemHw        net.HardwareAddr
	SeqMap       map[uint32]int64
	TCPLocalIp   net.IP
	TCPRemIp     net.IP
	LocalPort    layers.TCPPort
	RemPort      layers.TCPPort
	Seq          uint32
	Ack          uint32
	Ip4          *layers.IPv4
	Ip6          *layers.IPv6
	Dir          int
	IpDataLen    uint32
	Transport    layers.IPProtocol
	E2eLatencies []float64
}

const (
	In  = 0
	Out = 1
)

func (r *Receiver) NewReceiver(pktChan chan InputPkt, hostV4 net.IP, hostV6 net.IP, sendStartChan chan bool) {
	r.PktChan = pktChan
	r.LocalV4 = hostV4
	r.LocalV6 = hostV6
	r.SendStartChan = sendStartChan

	r.Curr = CurrStatus{}
	r.Curr.E2eLatencies = []float64{}
	r.Curr.SeqMap = make(map[uint32]int64)
}

func (r *Receiver) GetHardwareAddresses(pkt InputPkt) {
	ethLayer := pkt.Packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	r.Curr.LocalHw = eth.SrcMAC
	r.Curr.RemHw = eth.DstMAC
}

func (r *Receiver) ParseTcpIn(pkt InputPkt, tcp *layers.TCP) {
	pts := pkt.Packet.Metadata().Timestamp.UnixNano()
	if sts, ok := r.Curr.SeqMap[tcp.Ack]; ok == true {
		r.Curr.E2eLatencies = append(r.Curr.E2eLatencies, float64(pts-sts)/float64(time.Millisecond))
		delete(r.Curr.SeqMap, tcp.Ack)
	}
	r.Curr.Ack = tcp.Seq
	if tcp.SYN == true {
		r.Curr.Ack++
	}
}

func (r *Receiver) IsProbePacket(pkt InputPkt, tcp *layers.TCP) bool {
	if r.Curr.Ip4 != nil {
		if r.Curr.Ip4.TTL < 32 && r.Curr.Ip4.Id == uint16(r.Curr.Ip4.TTL) {
			return true
		}
	}
	// TODO IP6
	return false
}

func (r *Receiver) ParseTcpOut(pkt InputPkt, tcp *layers.TCP) {
	if r.IsProbePacket(pkt, tcp) {
		ip4L := pkt.Packet.Layer(layers.LayerTypeIPv4)
		ip4, _ := ip4L.(*layers.IPv4)
		fmt.Printf("Saw probe packet %+v\n", ip4)
	}

	if len(tcp.Payload) == 0 {
		return
	}

	seq := tcp.Seq + r.Curr.IpDataLen - uint32(tcp.DataOffset*4)
	r.Curr.SeqMap[seq] = pkt.Packet.Metadata().Timestamp.UnixNano()
	r.Curr.Seq = seq
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
}

func (r *Receiver) ParseTcpLayer(pkt InputPkt) error {
	tcpLayer := pkt.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return errors.New("not a TCP pkt")
	}

	tcp, _ := tcpLayer.(*layers.TCP)
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
		r.Curr.Ip4, _ = pkt.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		icmp, _ := icmp4Layer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
			fmt.Printf("ICMP time exceeded from %s\n", r.Curr.Ip4.SrcIP.String())
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
	fmt.Printf("Starting receiver\n")
	for {
		pkt := <-r.PktChan
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

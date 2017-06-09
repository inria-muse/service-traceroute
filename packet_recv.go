package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type Receiver struct {
	E2eLatencies  []float64
	PktChan       chan InputPkt
	LocalHw       net.HardwareAddr
	RemHw         net.HardwareAddr
	LocalV4       net.IP
	LocalV6       net.IP
	SeqMap        map[uint32]int64
	CurrSeq       uint32
	CurrAck       uint32
	LocalIp       net.IP
	RemIp         net.IP
	LocalPort     layers.TCPPort
	RemPort       layers.TCPPort
	SendStartChan chan bool
	HasSentSend   bool
}

const (
	In  = 0
	Out = 1
)

func (r *Receiver) NewReceiver(pktChan chan InputPkt, hostV4 net.IP, hostV6 net.IP, sendStartChan chan bool) {
	r.E2eLatencies = []float64{}
	r.PktChan = pktChan
	r.LocalV4 = hostV4
	r.LocalV6 = hostV6
	r.SeqMap = make(map[uint32]int64)
	r.SendStartChan = sendStartChan
}

func (r *Receiver) GetHardwareAddresses(pkt InputPkt) {
	ethLayer := pkt.Packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	r.LocalHw = eth.SrcMAC
	r.RemHw = eth.DstMAC
}

func (r *Receiver) ParseTcpIn(pkt InputPkt, tcp *layers.TCP) {
	pts := pkt.Packet.Metadata().Timestamp.UnixNano()
	if sts, ok := r.SeqMap[tcp.Ack]; ok == true {
		r.E2eLatencies = append(r.E2eLatencies, float64(pts-sts)/float64(time.Millisecond))
		delete(r.SeqMap, tcp.Ack)
	}
	fmt.Printf("AAA %+v\n", r.E2eLatencies)
	r.CurrAck = tcp.Seq
	if tcp.SYN == true {
		r.CurrAck++
	}
}

func (r *Receiver) ParseTcpOut(pkt InputPkt, tcp *layers.TCP, ipDataLen uint32) {
	if len(tcp.Payload) == 0 {
		return
	}
	seq := tcp.Seq + ipDataLen - uint32(tcp.DataOffset*4)
	r.SeqMap[seq] = pkt.Packet.Metadata().Timestamp.UnixNano()
	r.CurrSeq = seq
	if tcp.SYN == true {
		r.CurrSeq++
	}
	r.LocalPort = tcp.SrcPort
	r.RemPort = tcp.DstPort
	if r.HasSentSend == false && tcp.SYN == false {
		r.GetHardwareAddresses(pkt)
		r.SendStartChan <- true
		r.HasSentSend = true
	}
}

func (r *Receiver) ParseTcpLayer(pkt InputPkt, dir int, ipDataLen uint32) error {
	tcpLayer := pkt.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return errors.New("not a TCP pkt")
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if dir == In {
		r.ParseTcpIn(pkt, tcp)
	} else {
		r.ParseTcpOut(pkt, tcp, ipDataLen)
	}
	return nil
}

func (r *Receiver) ParseIcmpLayer(pkt InputPkt, dir int) error {
	if dir == Out {
		return errors.New("Outgoing ICMP")
	}
	if icmp4Layer := pkt.Packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		ip, _ := pkt.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		fmt.Printf("ICMP Pkt from %s\n", ip.SrcIP.String())
	}
	return nil
}

func (r *Receiver) ParseIpLayer(pkt InputPkt) (int, layers.IPProtocol, uint32, error) {
	dir := Out
	var ipDataLen uint32
	var transport layers.IPProtocol

	if ip4Layer := pkt.Packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)
		r.LocalIp = ip.SrcIP
		r.RemIp = ip.DstIP
		ipDataLen = uint32(ip.Length - 4*uint16(ip.IHL))
		if ip.DstIP.String() == r.LocalV4.String() {
			dir = In
			r.LocalIp = ip.DstIP
			r.RemIp = ip.SrcIP
		}
		transport = ip.Protocol
	} else if ip6Layer := pkt.Packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		r.LocalIp = ip.SrcIP
		r.RemIp = ip.DstIP
		ipDataLen = uint32(ip.Length)
		if ip.DstIP.String() == r.LocalV6.String() {
			dir = In
			r.LocalIp = ip.DstIP
			r.RemIp = ip.SrcIP
		}
		transport = ip.NextHeader

	} else {
		return 0, 0, 0, errors.New("Not IP")
	}
	return dir, transport, ipDataLen, nil
}

func (r *Receiver) Run() {
	for {
		pkt := <-r.PktChan
		dir, transport, ipDataLen, err := r.ParseIpLayer(pkt)
		if err != nil {
			continue
		}
		switch {
		case transport == layers.IPProtocolTCP:
			r.ParseTcpLayer(pkt, dir, ipDataLen)
		case transport == layers.IPProtocolICMPv4 || transport == layers.IPProtocolICMPv6:
			r.ParseIcmpLayer(pkt, dir)
		}
	}
}

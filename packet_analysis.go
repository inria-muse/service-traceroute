package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type PacketAnalyzer struct {
	Latencies []float64
	PktChan   chan InputPkt
	LocalV4   net.IP
	LocalV6   net.IP
	SeqMap    map[uint32]int64
}

const (
	In  = 0
	Out = 1
)

func (pa *PacketAnalyzer) NewPacketAnalyzer(pktChan chan InputPkt, hostV4 net.IP, hostV6 net.IP) {
	pa.Latencies = []float64{}
	pa.PktChan = pktChan
	pa.LocalV4 = hostV4
	pa.LocalV6 = hostV6
	pa.SeqMap = make(map[uint32]int64)

}

func (pa *PacketAnalyzer) ParseTcpIn(tcp *layers.TCP, pts int64) {
	if sts, ok := pa.SeqMap[tcp.Ack]; ok == true {
		fmt.Printf("In ack %d %f %f %f lat %f\n", tcp.Ack, float64(pts)/float64(time.Millisecond), float64(sts)/float64(time.Millisecond), float64(time.Millisecond), float64(pts-sts)/float64(time.Millisecond))
		delete(pa.SeqMap, tcp.Ack)
	}
}

func (pa *PacketAnalyzer) ParseTcpOut(tcp *layers.TCP, pts int64, ipDataLen uint32) {
	if len(tcp.Payload) == 0 {
		return
	}
	seq := tcp.Seq + ipDataLen - uint32(tcp.DataOffset*4)
	pa.SeqMap[seq] = pts
	fmt.Printf("Out seq %d\n", seq)
}

func (pa *PacketAnalyzer) ParseTcpLayer(pkt InputPkt, dir int, ipDataLen uint32) error {
	tcpLayer := pkt.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return errors.New("not a TCP pkt")
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if dir == In {
		pa.ParseTcpIn(tcp, pkt.Packet.Metadata().Timestamp.UnixNano())
	} else {
		pa.ParseTcpOut(tcp, pkt.Packet.Metadata().Timestamp.UnixNano(), ipDataLen)
	}
	return nil
}

func (pa *PacketAnalyzer) ParseIpLayer(pkt InputPkt) (int, uint32, error) {
	dir := Out
	var ipDataLen uint32

	if ip4Layer := pkt.Packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)
		ipDataLen = uint32(ip.Length - 4*uint16(ip.IHL))
		if ip.DstIP.String() == pa.LocalV4.String() {
			dir = In
		}
	} else if ip6Layer := pkt.Packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		ipDataLen = uint32(ip.Length)
		if ip.DstIP.String() == pa.LocalV6.String() {
			dir = In
		}
	} else {
		return 0, 0, errors.New("Not IP")
	}
	return dir, ipDataLen, nil
}

func (pa *PacketAnalyzer) Run() {
	for {
		pkt := <-pa.PktChan
		dir, ipDataLen, err := pa.ParseIpLayer(pkt)
		if err != nil {
			continue
		}
		pa.ParseTcpLayer(pkt, dir, ipDataLen)
	}
}

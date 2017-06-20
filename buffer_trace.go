package main

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type BufferTrace struct {
	SendQ        chan []gopacket.SerializableLayer
	R            *Receiver
	FlowSeqMap   map[uint32]int64
	ProbeIdMap   map[uint16]int64
	ProbeSeqMap  map[uint16]int64
	E2eLatencies []float64
	DoneSend     chan bool
	OutChan      chan string
}

func (bt *BufferTrace) NewBufferTrace(r *Receiver, sendQ chan []gopacket.SerializableLayer, outChan chan string) {
	bt.SendQ = sendQ
	bt.R = r
	bt.FlowSeqMap = make(map[uint32]int64)
	bt.ProbeIdMap = make(map[uint16]int64)
	bt.E2eLatencies = []float64{}
	bt.DoneSend = make(chan bool)
	bt.OutChan = outChan
}

func (bt *BufferTrace) SendPkts() {
	<-bt.R.SendStartChan

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       bt.R.Curr.LocalHw,
		DstMAC:       bt.R.Curr.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TOS:      0x10,
		Length:   40,
		SrcIP:    bt.R.Curr.TCPLocalIp,
		DstIP:    bt.R.Curr.TCPRemIp,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		DstPort:    layers.TCPPort(bt.R.Curr.RemPort),
		SrcPort:    layers.TCPPort(bt.R.Curr.LocalPort),
		DataOffset: 5,
		Seq:        0,
		Ack:        0,
		ACK:        true,
		Window:     0xffff,
	}
	for i := 0; i < 20; i++ {
		ipLayer.TTL = uint8(i + 1)
		ipLayer.Id = uint16(ipLayer.TTL)
		tcpLayer.Seq = bt.R.Curr.Seq
		tcpLayer.Ack = bt.R.Curr.Ack

		bt.SendQ <- []gopacket.SerializableLayer{ethernetLayer, ipLayer, tcpLayer}
		<-time.After(time.Millisecond * 10)
	}
	bt.DoneSend <- true
}

func (bt *BufferTrace) AnalyzePackets() {
	bt.OutChan <- fmt.Sprintf("%.3f Experiment analysis engine", float64(time.Now().UnixNano())/float64(time.Millisecond))
	for {
		select {
		case c := <-bt.R.FlowOutChan:
			bt.FlowSeqMap[c.Seq+c.IpDataLen-c.TcpHLen] = c.Ts
		case c := <-bt.R.FlowInChan:
			if sts, ok := bt.FlowSeqMap[c.Ack]; ok == true {
				bt.E2eLatencies = append(bt.E2eLatencies, float64(c.Ts-sts)/float64(time.Millisecond))
				delete(bt.FlowSeqMap, c.Ack)
			}
		case c := <-bt.R.ProbeOutChan:
			bt.ProbeIdMap[c.IpId] = c.Ts
		case c := <-bt.R.ProbeInChan:
			var id uint16 = binary.BigEndian.Uint16(c.IcmpPayload[4:6])
			if oTs, ok := bt.ProbeIdMap[id]; ok {
				bt.OutChan <- fmt.Sprintf("Probe latency from %s (hop %d): %.3f", c.RemIp.String(), id, float64(c.Ts-oTs)/float64(time.Millisecond))
				delete(bt.ProbeIdMap, id)
			}
		}
	}
}

func (bt *BufferTrace) Run() {
	bt.OutChan <- fmt.Sprintf("%.3f: Starting buffertrace experiment", float64(time.Now().UnixNano())/float64(time.Millisecond))
	go bt.AnalyzePackets()
	go bt.SendPkts()
	<-bt.DoneSend
}

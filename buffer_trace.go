package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type BufferTrace struct {
	SendQ    chan []gopacket.SerializableLayer
	R        *Receiver
	DoneSend chan bool
	OutChan  chan string
}

func (bt *BufferTrace) NewBufferTrace(r *Receiver, sendQ chan []gopacket.SerializableLayer, outChan chan string) {
	bt.R = r
	bt.SendQ = sendQ
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
		bt.OutChan <- fmt.Sprintf("%.3f: Sending packet %d", float64(time.Now().UnixNano())/float64(time.Millisecond), i)
		ipLayer.TTL = uint8(i + 1)
		ipLayer.Id = uint16(ipLayer.TTL)
		tcpLayer.Seq = bt.R.Curr.Seq
		tcpLayer.Ack = bt.R.Curr.Ack

		bt.SendQ <- []gopacket.SerializableLayer{ethernetLayer, ipLayer, tcpLayer}
		<-time.After(time.Millisecond * 10)
	}
	bt.DoneSend <- true
}

func (bt *BufferTrace) Run() {
	bt.OutChan <- fmt.Sprintf("%.3f: Starting buffertrace experiment", float64(time.Now().UnixNano())/float64(time.Millisecond))
	go bt.SendPkts()
	<-bt.DoneSend
}

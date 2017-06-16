package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type BufferTrace struct {
	StartChan chan bool
	SendQ     chan []gopacket.SerializableLayer
	R         *Receiver
	DoneSend  chan bool
}

func (bt *BufferTrace) NewBufferTrace(r *Receiver, startChan chan bool, sendQ chan []gopacket.SerializableLayer) {
	bt.StartChan = startChan
	bt.R = r
	bt.SendQ = sendQ
	bt.DoneSend = make(chan bool)
}

func (bt *BufferTrace) SendPkts() {
	<-bt.StartChan

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
		fmt.Printf("Sending packet %d\n", i)
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
	fmt.Printf("Starting buffertrace experiment\n")
	go bt.SendPkts()
	<-bt.DoneSend
}

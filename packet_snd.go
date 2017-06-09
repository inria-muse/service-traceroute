package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Sender struct {
	StartChan chan bool
	Iface     string
	R         *Receiver
}

func (s *Sender) NewSender(startChan chan bool, iface string, r *Receiver) {
	s.StartChan = startChan
	s.Iface = iface
	s.R = r
}

func (s *Sender) Run() {
	handle, err := pcap.OpenLive(s.Iface, int32(100), false, time.Duration(30*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	<-s.StartChan

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       s.R.LocalHw,
		DstMAC:       s.R.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TOS:      0x10,
		Length:   40,
		Id:       222,
		TTL:      0,
		SrcIP:    s.R.LocalIp,
		DstIP:    s.R.RemIp,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		DstPort:    layers.TCPPort(s.R.RemPort),
		SrcPort:    layers.TCPPort(s.R.LocalPort),
		DataOffset: 5,
		Seq:        0,
		Ack:        0,
		ACK:        true,
		Window:     0xffff,
	}

	buf := gopacket.NewSerializeBuffer()

	for i := 0; i < 10; i++ {
		ipLayer.TTL = uint8(i + 1)
		tcpLayer.Seq = s.R.CurrSeq
		tcpLayer.Ack = s.R.CurrAck
		buf.Clear()

		if err = tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
			log.Fatal(err)
		}

		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
		}

		if err = tcpLayer.SerializeTo(buf, opts); err != nil {
			log.Fatal(err)
		}

		if err = ipLayer.SerializeTo(buf, opts); err != nil {
			log.Fatal(err)
		}

		if err = ethernetLayer.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
			log.Fatal(err)
		}

		if err = handle.WritePacketData(buf.Bytes()); err != nil {
			log.Fatal(err)
		}

		log.Printf("packet sent! %s %s %d %d %d %d\n", s.R.LocalIp.String(), s.R.RemIp.String(), s.R.RemPort, s.R.LocalPort, s.R.CurrSeq, s.R.CurrAck)
		time.Sleep(time.Millisecond * 100)
	}

}

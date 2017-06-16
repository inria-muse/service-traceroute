package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Sender struct {
	Iface string
	R     *Receiver
	SendQ chan []gopacket.SerializableLayer
}

func (s *Sender) NewSender(iface string, r *Receiver, sendQ chan []gopacket.SerializableLayer) {
	s.Iface = iface
	s.R = r
	s.SendQ = sendQ
}

func (s *Sender) Run() {
	fmt.Printf("Starting sender\n")
	handle, err := pcap.OpenLive(s.Iface, int32(100), false, time.Duration(30*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	buf := gopacket.NewSerializeBuffer()

	for {
		outPktL := <-s.SendQ

		buf.Clear()

		optsCSum := gopacket.SerializeOptions{
			ComputeChecksums: true,
		}

		for i := len(outPktL) - 1; i >= 0; i-- {
			layer := outPktL[i]
			opts := gopacket.SerializeOptions{}
			if tcpL, ok := layer.(*layers.TCP); ok {
				if i == 0 {
					log.Fatal(errors.New("TCP layer without IP Layer"))
				}
				if ipL, ok := outPktL[i-1].(*layers.IPv4); ok {
					if err = tcpL.SetNetworkLayerForChecksum(ipL); err != nil {
						log.Fatal(err)
					}
				}
				//TODO v6
				opts = optsCSum
			}
			if _, ok := layer.(*layers.IPv4); ok {
				opts = optsCSum
			}
			//TODO v6
			if err = layer.SerializeTo(buf, opts); err != nil {
				log.Fatal(err)
			}
		}

		if err = handle.WritePacketData(buf.Bytes()); err != nil {
			log.Fatal(err)
		}

		fmt.Printf("packet sent!\n")
	}
}

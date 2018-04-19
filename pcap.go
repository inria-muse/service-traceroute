package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PcapHandler struct {
	BufferMb int
	SnapLen  int
	Filter   string
	Iface    string
	LocalV4  net.IP
	LocalV6  net.IP
	PktChan  chan *gopacket.Packet
	OutChan  chan string
	DoneChan chan bool
	StopChan chan bool

	Handler *pcap.Handle

	Ready        chan bool
	Sniffing     bool //If true, uses PcapHandler, otherwise SniffingChannel
	SniffingChan chan *gopacket.Packet
}

func (ph *PcapHandler) NewPacketHandlerFromChannel(sniffingChannel chan *gopacket.Packet, pktChan chan *gopacket.Packet, outChan chan string, ready chan bool) {
	ph.SniffingChan = sniffingChannel
	ph.PktChan = pktChan
	ph.OutChan = outChan
	ph.Ready = ready
	ph.Sniffing = false

	ph.StopChan = make(chan bool)
	ph.DoneChan = make(chan bool)
}

func (ph *PcapHandler) NewPacketHandler(cap CapThread, iface string, proto string, ip string, port int, pktChan chan *gopacket.Packet, outChan chan string, ready chan bool) {
	ph.Iface = iface
	ph.SnapLen = cap.CapSize
	ph.BufferMb = cap.Buffer
	ph.Filter = cap.BPF
	ph.PktChan = pktChan
	ph.OutChan = outChan
	ph.Ready = ready
	ph.Sniffing = true
	ph.DoneChan = make(chan bool)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	validAddress := false

	for _, iface := range devices {
		if iface.Name == ph.Iface {
			netIface, err := net.InterfaceByName(ph.Iface)
			if err != nil {
				log.Fatal(err)
			}
			addrs, _ := netIface.Addrs()
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.IsGlobalUnicast() && v.IP.To4() != nil {
						ph.LocalV4 = (*v).IP
						if proto == V4 {
							validAddress = true
						}
					} else if v.IP.IsGlobalUnicast() && v.IP.To16() != nil {
						ph.LocalV6 = (*v).IP
						if proto == V6 {
							validAddress = true
						}
					}
				}
			}
		}
	}

	if !validAddress {
		log.Fatal("No valid IP for interface")
	}

	if ip != "" && cap.BPF != Icmp {
		ph.Filter += " and host " + ip
	}

	if port != 0 && cap.BPF != Icmp {
		ph.Filter += " and port " + fmt.Sprintf("%d", port)
	}

	//fmt.Printf("Filters %s\n", ph.Filter)
}

func (ph *PcapHandler) Run() {
	if ph.Sniffing {
		ph.RunSniffing()
	} else {
		ph.RunChannelListener()
	}
}

func (ph *PcapHandler) RunChannelListener() {
	ph.Ready <- true

	defer func() {
		ph.DoneChan <- true
	}()

	for {
		select {
		case <-ph.StopChan:
			return
		case packet := <-ph.SniffingChan:
			ph.PktChan <- packet
		}
	}
}

func (ph *PcapHandler) RunSniffing() {
	inactiveHandle, err := pcap.NewInactiveHandle(ph.Iface)
	if err != nil {
		log.Fatal(err)
	}

	inactiveHandle.SetSnapLen(ph.SnapLen)
	inactiveHandle.SetTimeout(pcap.BlockForever)
	inactiveHandle.SetBufferSize(1e6 * ph.BufferMb)

	handle, err := inactiveHandle.Activate()
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		handle.Close()
		ph.DoneChan <- true
	}()

	err = handle.SetBPFFilter(ph.Filter)
	if err != nil {
		log.Fatal(err)
	}

	ph.Handler = handle
	ph.Ready <- true

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ph.PktChan <- &packet
	}
}

//TODO: stop sniffing with pcap handler
func (ph *PcapHandler) Stop() {
	if ph.Sniffing {
		ph.Handler.Close()
	} else {
		ph.StopChan <- true
	}
}

package main

import (
	"fmt"
	"log"
	"net"

	"tracetcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PcapExt struct {
	BufferMb int
	SnapLen  int
	Filter   string
	Iface    string
	LocalV4  net.IP
	LocalV6  net.IP
	PktChan  chan gopacket.Packet
	OutChan  chan string
	DoneChan chan bool
	StopChan chan bool

	Handler *pcap.Handle

	Ready        chan bool
	Sniffing     bool //If true, uses PcapHandler, otherwise SniffingChannel
	SniffingChan chan gopacket.Packet
}

func (ph *PcapExt) NewPacketHandler(cap tracetcp.CapThread, iface string, proto string, ip string, port int, pktChan chan gopacket.Packet, outChan chan string, ready chan bool) {
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
						if proto == tracetcp.V4 {
							validAddress = true
						}
					} else if v.IP.IsGlobalUnicast() && v.IP.To16() != nil {
						ph.LocalV6 = (*v).IP
						if proto == tracetcp.V6 {
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

	if ip != "" && cap.BPF != tracetcp.Icmp {
		ph.Filter += " and host " + ip
	}

	if port != 0 && cap.BPF != tracetcp.Icmp {
		ph.Filter += " and port " + fmt.Sprintf("%d", port)
	}

	//fmt.Printf("Filters %s\n", ph.Filter)
}

func (ph *PcapExt) Run() {
	if ph.Sniffing {
		ph.RunSniffing()
	}
}

func (ph *PcapExt) RunSniffing() {
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
		ph.PktChan <- packet
	}
}

//TODO: stop sniffing with pcap handler
func (ph *PcapExt) Stop() {
	if ph.Sniffing {
		ph.Handler.Close()
	} else {
		ph.StopChan <- true
	}
}

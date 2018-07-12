package tracetcp

import (
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

//Structure for sending packets to the interface
type Sender struct {
	Iface   string
	SendQ   chan []byte
	OutChan chan string

	StopChan chan bool
	DoneChan chan bool
}

//Initialize and configure a new sender
func (s *Sender) NewSender(iface string, outChan chan string) {
	s.Iface = iface
	s.SendQ = make(chan []byte, 1000)
	s.OutChan = outChan

	s.StopChan = make(chan bool)
	s.DoneChan = make(chan bool)
}

//Run a listener for packets to be transmitted
func (s *Sender) Run() {
	handle, err := pcap.OpenLive(s.Iface, int32(100), false, time.Duration(30*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	defer func() {
		s.DoneChan <- true
	}()

	for {
		select {
		case <-s.StopChan:
			return
		case outPkt := <-s.SendQ:
			if err = handle.WritePacketData(outPkt); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func (s *Sender) Stop() {
	s.StopChan <- true
}

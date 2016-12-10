// tcp.go - rough TCP packet crafting facility.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of rough, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package rough

import (
	"fmt"
	"log"
	badrand "math/rand"
	"net"
	"time"

	"github.com/nogoegst/gopacket"
	"github.com/nogoegst/gopacket/layers"
	"github.com/nogoegst/gopacket/pcap"
)

type TCP struct {
	Pkt        *layers.TCP
	TX         chan *layers.TCP
	RX         chan *layers.TCP
	txStatus   chan struct{}
	rxStatus   chan struct{}
	SrcLLAddr  net.HardwareAddr
	DstLLAddr  net.HardwareAddr
	LocalAddr  net.IP
	RemoteAddr net.IP
	LocalPort  uint16
	RemotePort uint16
	device     string
	handle     *pcap.Handle
}

func (s *TCP) Open() {
	s.RX = make(chan *layers.TCP, 16)
	s.TX = make(chan *layers.TCP)
	s.rxStatus = make(chan struct{})
	s.txStatus = make(chan struct{})
	s.Pkt = &layers.TCP{
		SrcPort: layers.TCPPort(s.LocalPort),
		DstPort: layers.TCPPort(s.RemotePort),
	}

	handle, err := pcap.OpenLive(s.device, 2048, false, 1*time.Microsecond)
	if err != nil {
		log.Fatal(err)
	}
	s.handle = handle
	filter := fmt.Sprintf("tcp and src %s and src port %d and dst %s and dst port %d", s.RemoteAddr, s.RemotePort, s.LocalAddr, s.LocalPort)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	go s.RXLoop()
	go s.TXLoop()

}

func (s *TCP) Close() {
	close(s.TX)
	close(s.rxStatus)
	s.handle.Close()
}

func (s *TCP) RXLoop() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packets := packetSource.Packets()
	for {
		select {
		case _, ok := <-s.rxStatus:
			if !ok {
				goto DoneRX
			}
		case packet, more := <-packets:
			if !more {
				goto DoneRX
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			tcp, _ := tcpLayer.(*layers.TCP)
			s.RX <- tcp
		}
	}
DoneRX:
	close(s.RX)
	return
}

func (s *TCP) TXLoop() {
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       s.SrcLLAddr,
		DstMAC:       s.DstLLAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    s.LocalAddr,
		DstIP:    s.RemoteAddr,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	for {
		tcpLayer, more := <-s.TX
		if !more {
			close(s.txStatus)
			return
		}
		tcpLayer.SetNetworkLayerForChecksum(ipLayer)

		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, options,
			ethernetLayer,
			ipLayer,
			tcpLayer,
			gopacket.Payload(tcpLayer.Payload),
		)

		outgoingPacket := buffer.Bytes()

		//retries := 0
	Inject:
		_, err := s.handle.WritePacketData(outgoingPacket)
		if err != nil {
			//retries += 1
			// backoff
			time.Sleep(time.Duration(badrand.Intn(50)) * time.Microsecond)
			goto Inject
		}
		//if retries != 0 {
		//	log.Printf("Injected after %d retries", retries)
		//}
		s.txStatus <- struct{}{}
	}
}

func (s *TCP) WaitTX() {
	<-s.txStatus
}

func (s *TCP) SendOut() {
	s.TX <- s.Pkt
}

type Routing struct {
	Device    string
	SrcLLAddr net.HardwareAddr
	DstLLAddr net.HardwareAddr
	SrcIPAddr net.IP
}

func (s *TCP) SetRouting(r Routing) {
	s.device = r.Device
	s.DstLLAddr = r.DstLLAddr
	s.SrcLLAddr = r.SrcLLAddr
	s.LocalAddr = r.SrcIPAddr
}

func (s *TCP) DoHandshake(result chan<- bool) {
	s.Pkt.Seq = RandUint32()
	s.Pkt.SYN = true
	s.SendOut()
	s.WaitTX()
	//log.Printf("> [SYN] Ack: %d, Seq: %d\n", s.Pkt.Ack, s.Pkt.Seq)
	timeout := time.After(15 * time.Second)
	var tcpIn *layers.TCP
SYNACK:
	for {
		select {
		case <-timeout:
			result <- false
			return
		case tcp, ok := <-s.RX:
			if !ok {
				log.Printf("RX channel closed")
				result <- false
				return
			}
			if tcp.SYN && tcp.ACK && tcp.Ack == s.Pkt.Seq+1 {
				tcpIn = tcp
				break SYNACK
			}
			result <- false
			return
		}
	}
	//log.Printf("< [SYN-ACK] Ack: %d, Seq: %d\n", tcpIn.Ack, tcpIn.Seq)

	s.Pkt.SYN = false
	s.Pkt.ACK = true
	s.Pkt.Ack = tcpIn.Seq + 1
	s.Pkt.Seq += 1
	//log.Printf("> [ACK] Ack: %d, Seq: %d\n", s.Pkt.Ack, s.Pkt.Seq)
	s.SendOut()
	s.WaitTX()
	result <- true
}

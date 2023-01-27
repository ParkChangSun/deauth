package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SimpleRadioTap struct {
	HeaderRevision   uint8
	HeaderPad        uint8
	HeaderLength     uint16
	Present1         uint32
	Present2         uint32
	Flags            uint8
	DataRate         uint8
	ChannelFrequency uint16
	ChannelFlags     uint16
	AnthenaSignal    uint16
	RxFlags          uint16
	AnthenaSignalDup uint16
}

type SimpleDot11 struct {
	Type               uint16
	Duration           uint16
	DestinationAddress [6]byte
	SourceAddress      [6]byte
	BssId              [6]byte
	FragSeqNum         uint16
}

type SimpleDot11Beacon struct {
	Timestamp uint64
	Interval  uint16
	Flags     uint16
}

type SimpleDot11Info struct {
	Number  uint8
	Length  uint8
	Content string
}

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func main() {
	args := os.Args

	handle, err := pcap.OpenLive(args[1], 2048, true, pcap.BlockForever)
	PanicError(err)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dot11 := packet.Layer(layers.LayerTypeDot11)
		if dot11 == nil {
			continue
		}
		d, _ := dot11.(*layers.Dot11)
		fmt.Print(d)
		buf := gopacket.NewSerializeBuffer()
		opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		d.SerializeTo(buf, opt)
	}
}

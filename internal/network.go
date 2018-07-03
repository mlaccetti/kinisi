package internal

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/juju/loggo"
)

var log = loggo.GetLogger("network")

func Start(iface *string, snaplen *int, filter *string, ipv4 *bool, ipv6 *bool, verboseMode *bool, resolveDns *bool)  {
	pcapHandle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Criticalf("Could not open pcapHandle: %v", err)
		return
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, layers.LinkTypeEthernet)
	packetSource.Lazy = true
	packetSource.NoCopy = true
	packetSource.DecodeStreamsAsDatagrams = true

	var eth layers.Ethernet
	var tcp layers.TCP
	var udp layers.UDP
	var ip4 layers.IPv4
	var ip6 layers.IPv6

	var decodingLayer = []gopacket.DecodingLayer {
		&eth, &tcp, &udp,
	}

	if *ipv4 {
		decodingLayer = append(decodingLayer, &ip4)
	}

	if *ipv6 {
		decodingLayer = append(decodingLayer, &ip6)
	}


	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, decodingLayer...)
	var decoded []gopacket.LayerType

	for packet := range packetSource.Packets() {
		parser.DecodeLayers(packet.Data(), &decoded)

		for _, layerType := range decoded {


			switch layerType {
			case layers.LayerTypeIPv4:
				log.Debugf("    IPv4: %v -> %v", ip4.NetworkFlow().Src().String(), ip4.NetworkFlow().Dst().String())
			case layers.LayerTypeIPv6:
				log.Debugf("    IPv6: %v -> %v ", ip6.NetworkFlow().Src().String(), ip6.NetworkFlow().Dst().String())
			case layers.LayerTypeTCP:
				log.Debugf("    TCP: %v -> %v :: %v ", tcp.SrcPort.String(), tcp.DstPort.String(), len(tcp.Payload))
			case layers.LayerTypeUDP:
				log.Debugf("    UDP: %v -> %v :: %v ", udp.SrcPort.String(), udp.DstPort.String(), len(udp.Payload))
			}
		}
	}
}

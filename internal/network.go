package internal

import (
	"context"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/juju/loggo"
)

type Traffic struct {
	ipType string
	layerType string
	src string
	dst string
	srcPort uint16
	dstPort uint16
	len uint16
}

var log = loggo.GetLogger("network")

func GoogleDnsDialer (ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "udp", "1.1.1.1:53")
}

func Start(c chan<- Traffic, iface *string, snaplen *int, filter *string, ipv4 *bool, ipv6 *bool, verboseMode *bool, resolveDns *bool) {
	pcapHandle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Criticalf("Could not open pcapHandle: %v", err)
		return
	}

	if *filter != "" {
		log.Infof("Setting packet filter to: [ %s ]", *filter)
		pcapHandle.SetBPFFilter(*filter)
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

		var t = Traffic {
			len: uint16(len(packet.Data())),
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				t.src = ip4.NetworkFlow().Src().String()
				t.dst = ip4.NetworkFlow().Dst().String()
				t.ipType = "ip4"
			case layers.LayerTypeIPv6:
				t.src = ip6.NetworkFlow().Src().String()
				t.dst = ip6.NetworkFlow().Dst().String()
				t.ipType = "ip6"
			case layers.LayerTypeTCP:
				t.srcPort = uint16(tcp.SrcPort)
				t.dstPort = uint16(tcp.DstPort)
				t.layerType = "tcp"
			case layers.LayerTypeUDP:
				t.srcPort = uint16(udp.SrcPort)
				t.dstPort = uint16(udp.DstPort)
				t.layerType = "udp"
			}
		}

		if *resolveDns {
			r := net.Resolver{
				PreferGo: true,
				Dial: GoogleDnsDialer,
			}

			ctx := context.Background()

			resolvedSrc, err := r.LookupAddr(ctx, t.src)
			if err == nil {
				t.src = strings.TrimSuffix(resolvedSrc[len(resolvedSrc)-1], ".")
			}

			resolvedDst, err := r.LookupAddr(ctx, t.dst)
			if err == nil {
				t.dst = strings.TrimSuffix(resolvedDst[len(resolvedDst)-1], ".")
			}
		}

		if t.layerType != "" && t.layerType != "udp" && t.dstPort != 53 {
			log.Debugf("ip type: %s | layer type: %s | src: %v | src port: %d | dst: %s | dst port: %d | len: %d", t.ipType, t.layerType, t.src, t.srcPort, t.dst, t.dstPort, t.len)
		}

		c <- t
	}
}

package internal

import (
	"context"
	"net"

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
	srcPort string
	dstPort string
	len int
}

var log = loggo.GetLogger("network")

func GoogleDnsDialer (ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "udp", "1.1.1.1:53")
}

func Start(errs chan<- error, c chan<- Traffic, iface *string, snaplen *int, filter *string, ipv4 *bool, ipv6 *bool, verboseMode *bool, resolveDns *bool) {
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

		var t = Traffic {
			len: len(packet.Data()),
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
				t.srcPort = tcp.SrcPort.String()
				t.dstPort = tcp.DstPort.String()
				t.layerType = "tcp"
			case layers.LayerTypeUDP:
				t.srcPort = udp.SrcPort.String()
				t.dstPort = udp.DstPort.String()
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
				t.src = resolvedSrc[len(resolvedSrc)-1]
			}

			resolvedDst, err := r.LookupAddr(ctx, t.dst)
			if err == nil {
				t.dst = resolvedDst[len(resolvedDst)-1]
			}
		}

		if t.layerType != "" && t.layerType != "udp" && t.dstPort != "53" {
			log.Debugf("ip type: %s | layer type: %s | src: %v | src port: %s | dst: %s | dst port: %s | len: %b", t.ipType, t.layerType, t.src, t.srcPort, t.dst, t.dstPort, t.len)
		}

		c <- t
	}
}

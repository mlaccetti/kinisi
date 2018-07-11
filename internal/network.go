package internal

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/juju/loggo"
	"github.com/patrickmn/go-cache"
)

type Traffic struct {
	ipType string
	layerType string
	src string
	dst string
	srcPort int
	dstPort int
	len int
}

var log = loggo.GetLogger("network")

func GoogleDnsDialer (ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "udp", "1.1.1.1:53")
}

func Start(c chan<- Traffic, iface *string, snaplen *int, filter *string, ipv4 *bool, ipv6 *bool, resolveDns *bool) {
	var timedCache = cache.New(2*time.Minute, 4*time.Minute)
	timedCache.OnEvicted(func(s string, i interface{}) {
		t := i.(Traffic)
		t.len = 0
		log.Debugf("Expiring %v - %v", s, t)
		c <- t
	})

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
			len: int(len(packet.Data())),
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
				t.srcPort = int(tcp.SrcPort)
				t.dstPort = int(tcp.DstPort)
				t.layerType = "tcp"

				log.Debugf("SYN: %t | ACK: %t | RST: %t | FIN: %t", tcp.SYN, tcp.ACK, tcp.RST, tcp.FIN)

				srcVal := t.src + ":" + strconv.Itoa(t.srcPort)
				dstVal := t.dst + ":" + strconv.Itoa(t.dstPort)

				if tcp.SYN && !tcp.ACK {
					log.Tracef("SYN packet found, adding to cache as key: %v | value: %v", dstVal, t)
					timedCache.Set(dstVal, t, cache.DefaultExpiration)
				} else {
					log.Tracef("No SYN packet found, looking up in cache as %v", dstVal)
					if _, found := timedCache.Get(dstVal); found != true {
						log.Tracef("Could not find in cache as %v, looking up as %v", dstVal, srcVal)
						if _, found := timedCache.Get(srcVal); found != true {
							log.Warningf("Could not find %v or %v in cache", dstVal, srcVal)
						} else {
							log.Tracef("Swapping source and dest")
							tempDst := t.dst
							t.dst = t.src
							t.src = tempDst

							tempDstPort := t.dstPort
							t.dstPort = t.srcPort
							t.srcPort = tempDstPort
						}
					} else {
						log.Tracef("Found stream originator in cache as %v %v, nothing to do.", srcVal, dstVal)
					}
				}
			case layers.LayerTypeUDP:
				t.srcPort = int(udp.SrcPort)
				t.dstPort = int(udp.DstPort)
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

		if t.layerType != "" {
			log.Debugf("ip type: %s | layer type: %s | src: %v | src port: %d | dst: %s | dst port: %d | len: %d", t.ipType, t.layerType, t.src, t.srcPort, t.dst, t.dstPort, t.len)
		}

		c <- t
	}
}

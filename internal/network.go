package internal

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/juju/loggo"
)

// simpleStreamFactory implements tcpassembly.StreamFactory
type statsStreamFactory struct{}

// statsStream will handle the actual decoding of stats requests.
type statsStream struct {
	net, transport                      gopacket.Flow
	bytes, packets, outOfOrder, skipped int64
	start, end                          time.Time
	sawStart, sawEnd                    bool
}

type StringFlow struct {
	net gopacket.Flow
	src[] string
	dst[] string
}

var _resolveDns = false
var log = loggo.GetLogger("network")

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func (factory *statsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	log.Infof("new stream %v:%v started", net, transport)
	s := &statsStream{
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	s.end = s.start
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return s
}

// Reassembled is called whenever new packet data is available for reading.
// Reassembly objects contain stream data IN ORDER.
func (s *statsStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytes += int64(len(reassembly.Bytes))
		s.packets += 1
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}
}

func GoogleDnsDialer (ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "udp", "1.1.1.1:53")
}

// ReassemblyComplete is called when the TCP assembler believes a stream has
// finished.
func (s *statsStream) ReassemblyComplete() {
	diffSecs := float64(s.end.Sub(s.start)) / float64(time.Second)

	dumpNet := StringFlow{
		net: s.net,
	}

	if _resolveDns {
		r := net.Resolver{
			PreferGo: true,
			Dial: GoogleDnsDialer,
		}

		ctx := context.Background()
		srcString := s.net.Src().String()
		src, err := r.LookupAddr(ctx, srcString)
		if err != nil {
			log.Infof("Could not resolve source address (%v): %v", srcString, err)
		} else {
			dumpNet.src = src
		}

		dstString := s.net.Dst().String()
		dst, err := r.LookupAddr(ctx, dstString)
		if err != nil {
			log.Infof("Could not resolve destination address (%v): %v", dstString, err)
		} else {
			dumpNet.dst = dst
		}
	}

	log.Infof("Reassembly of stream %v:%v complete - start:%v end:%v bytes:%v packets:%v ooo:%v bps:%v pps:%v skipped:%v",
		dumpNet, s.transport, s.start, s.end, s.bytes, s.packets, s.outOfOrder,
		float64(s.bytes)/diffSecs, float64(s.packets)/diffSecs, s.skipped)
}

func Start(flushAfter *string, iface *string, snaplen *int, filter *string, bufferedPerConnection *int, bufferedTotal *int, packetCount *int,
	logAllPackets *bool, resolveDns *bool)  {
	_resolveDns = *resolveDns
	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Criticalf("invalid flush duration: ", flushAfter)
	}

	log.Infof("DNS resolution enabled: %t", *resolveDns)

	log.Infof("starting capture on interface %v", *iface)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, flushDuration/2)
	if err != nil {
		log.Criticalf("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Criticalf("error setting BPF filter: ", err)
	}

	// Set up assembly
	streamFactory := &statsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = *bufferedPerConnection
	assembler.MaxBufferedPagesTotal = *bufferedTotal

	log.Infof("reading in packets")

	// We use a DecodingLayerParser here instead of a simpler PacketSource.
	// This approach should be measurably faster, but is also more rigid.
	// PacketSource will handle any known type of packet safely and easily,
	// but DecodingLayerParser will only handle those packet types we
	// specifically pass in.  This trade-off can be quite useful, though, in
	// high-throughput situations.
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &udp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	nextFlush := time.Now().Add(flushDuration / 2)

	var byteCount int64
	start := time.Now()

loop:
	for ; *packetCount != 0; *packetCount-- {
		// Check to see if we should flush the streams we have
		// that haven't seen any new data in a while.  Note we set a
		// timeout on our PCAP handle, so this should happen even if we
		// never see packet data.
		if time.Now().After(nextFlush) {
			stats, _ := handle.Stats()
			log.Infof("flushing all streams that haven't seen packets in the last 2 minutes, pcap stats: %+v", stats)
			assembler.FlushOlderThan(time.Now().Add(flushDuration))
			nextFlush = time.Now().Add(flushDuration / 2)
		}

		// To speed things up, we're also using the ZeroCopy method for
		// reading packet data.  This method is faster than the normal
		// ReadPacketData, but the returned bytes in 'data' are
		// invalidated by any subsequent ZeroCopyReadPacketData call.
		// Note that tcpassembly is entirely compatible with this packet
		// reading method.  This is another trade-off which might be
		// appropriate for high-throughput sniffing:  it avoids a packet
		// copy, but its cost is much more careful handling of the
		// resulting byte slice.
		data, ci, err := handle.ZeroCopyReadPacketData()

		if err != nil {
			log.Errorf("error getting packet: %v", err)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Errorf("error decoding packet: %v", err)
			continue
		}
		if *logAllPackets {
			log.Debugf("decoded the following layers: %v", decoded)
		}
		byteCount += int64(len(data))
		// Find either the IPv4 or IPv6 address to use as our network
		// layer.
		foundNetLayer := false
		var netFlow gopacket.Flow
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				netFlow = ip4.NetworkFlow()
				foundNetLayer = true
			case layers.LayerTypeIPv6:
				netFlow = ip6.NetworkFlow()
				foundNetLayer = true
			case layers.LayerTypeTCP:
				if foundNetLayer {
					assembler.AssembleWithTimestamp(netFlow, &tcp, ci.Timestamp)
				} else {
					log.Infof("could not find IPv4 or IPv6 layer, inoring")
				}
				continue loop
			}
		}
		log.Infof("could not find TCP layer")
	}
	assembler.FlushAll()
	log.Infof("processed %d bytes in %v", byteCount, time.Since(start))
}

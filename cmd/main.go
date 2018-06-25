package cmd

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket/dumpcommand"
	"github.com/google/gopacket/pfring"
	"github.com/mlaccetti/kinisi/internal"
)

func main() {
	retVal := SnarfPackets(false)
	os.Exit(retVal)
}

func SnarfPackets(testMode bool) int {
	viper := internal.Config()

	if viper.IsSet("help") && viper.GetBool("help") {
		internal.PrintHelp()
		return 0
	}

	if !viper.IsSet("verbose") || !viper.GetBool("verbose") {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	} else {
		log.Println("Verbose mode: enabled")
	}

	if !testMode {
		var iface = viper.GetString("interface")
		var snaplen = viper.GetInt("snaplen")
		var cluster = viper.GetInt("cluster")
		var clustertype = viper.GetInt("clustertype")

		var ring *pfring.Ring
		var err error
		if ring, err = pfring.NewRing(iface, uint32(snaplen), pfring.FlagPromisc); err != nil {
			log.Fatalln("pfring ring creation error:", err)
		}
		if len(flag.Args()) > 0 {
			bpffilter := strings.Join(flag.Args(), " ")
			fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
			if err = ring.SetBPFFilter(bpffilter); err != nil {
				log.Fatalln("BPF filter error:", err)
			}
		}
		if cluster >= 0 {
			if err = ring.SetCluster(cluster, pfring.ClusterType(clustertype)); err != nil {
				log.Fatalln("pfring SetCluster error:", err)
			}
		}
		if err = ring.SetSocketMode(pfring.ReadOnly); err != nil {
			log.Fatalln("pfring SetSocketMode error:", err)
		} else if err = ring.Enable(); err != nil {
			log.Fatalln("pfring Enable error:", err)
		}

		dumpcommand.Run(ring)
	}

	return 0
}
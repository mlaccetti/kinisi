package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/mlaccetti/kinisi/internal"
)

func main() {
	retVal := _SnarfPackets(false)
	os.Exit(retVal)
}

func _SnarfPackets(testMode bool) int {
	viper := internal.Config()

	if viper.IsSet("help") && viper.GetBool("help") {
		internal.PrintHelp()
		return 0
	}

	verboseMode := viper.GetBool("verbose")
	if !viper.IsSet("verbose") || verboseMode == false {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	} else {
		log.Println("Verbose mode: enabled")
	}

	var iface = viper.GetString("interface")
	var snaplen = viper.GetInt("snaplen")
	var filter = viper.GetString("filter")
	var connectionMaxBuffer = viper.GetInt("connection_max_buffer")
	var totalMaxBuffer = viper.GetInt("total_max_buffer")
	var flushAfter = viper.GetString("flush_after")
	var packetCount = viper.GetInt("packet_count")
	var resolveDns = viper.GetBool("resolve_dns")

	internal.Start(&flushAfter, &iface, &snaplen, &filter, &connectionMaxBuffer, &totalMaxBuffer, &packetCount, &verboseMode, &resolveDns)

	return 0
}

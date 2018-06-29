package main

import (
	"os"

	"github.com/juju/loggo"
	"github.com/juju/loggo/loggocolor"
	"github.com/mlaccetti/kinisi/internal"
)

var log = loggo.GetLogger("")

func init() {
	loggo.ConfigureLoggers("<root>=TRACE")
}

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
	if viper.IsSet("verbose") && verboseMode == true {
		var traceWriter = loggo.NewMinimumLevelWriter(loggocolor.NewWriter(os.Stderr), loggo.TRACE)
		loggo.ReplaceDefaultWriter(traceWriter)
		log.Infof("Verbose mode: enabled")
	} else {
		var infoWriter = loggo.NewMinimumLevelWriter(loggocolor.NewWriter(os.Stderr), loggo.INFO)
		loggo.ReplaceDefaultWriter(infoWriter)
	}

	log.Infof("kinisi online, snarfing traffic.")
	var iface = viper.GetString("interface")
	var snaplen = viper.GetInt("snaplen")
	var filter = viper.GetString("filter")
	var resolveDns = viper.GetBool("resolve_dns")

	internal.Start(&iface, &snaplen, &filter, &verboseMode, &resolveDns)

	return 0
}

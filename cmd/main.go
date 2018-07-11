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
		var traceWriter = loggo.NewMinimumLevelWriter(loggocolor.NewWriter(os.Stderr), loggo.DEBUG)
		loggo.ReplaceDefaultWriter(traceWriter)
		log.Infof("Verbose mode: enabled")
	} else {
		var infoWriter = loggo.NewMinimumLevelWriter(loggocolor.NewWriter(os.Stderr), loggo.INFO)
		loggo.ReplaceDefaultWriter(infoWriter)
	}

	var listen = viper.GetString("listen")
	var iface = viper.GetString("interface")
	var snaplen = viper.GetInt("snaplen")
	var ip4 = viper.GetBool("ip4")
	var ip6 = viper.GetBool("ip6")
	var filter = viper.GetString("filter")
	var resolveDns = viper.GetBool("resolve_dns")

	log.Infof("kinisi online, snarfing traffic on %v (ip4: %t, ip6: %t); dns resolution enabled: %t", iface, ip4, ip6, resolveDns)

	errs := make(chan error)
	go internal.PrometheusHttpServer(errs, &listen)

	var c = make(chan internal.Traffic)
	go internal.Start(c, &iface, &snaplen, &filter, &ip4, &ip6, &resolveDns)
	go internal.MetricHandler(c)

	select {
	case err := <-errs:
		log.Criticalf("Could not start snarf traffic due to error: %v", err)
		return 1
	}

	return 0
}

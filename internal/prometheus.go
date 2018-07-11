package internal

import (
"net/http"
"strconv"



"github.com/prometheus/client_golang/prometheus"
"github.com/prometheus/client_golang/prometheus/promhttp"

)

var networkTraffic = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "points",
		Subsystem: "network",
		Name:      "network_traffic",
		Help:      "Network connections, partitioned by IP4/6, protocol (TCP/UDP), and source/destination",
	},
	[]string{"network_layer", "transport_layer", "source", "source_port", "destination", "destination_port"},
)

func init() {
	prometheus.Register(networkTraffic)
}

func PrometheusHttpServer(errs chan<- error, listen *string) {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(*listen, nil)

	if err != nil {
		log.Criticalf("Could not launch Prometheus metrics listener: %v", err)
		errs <- err
	}
}

func MetricHandler(c <-chan Traffic) {
	for {
		t := <-c

		if t.len == 0 {
			log.Debugf("Removing %v", t)
			networkTraffic.DeleteLabelValues(t.ipType, t.layerType, t.src, strconv.Itoa(int(t.srcPort)), t.dst, strconv.Itoa(int(t.dstPort)))
		} else {
			networkTraffic.WithLabelValues(t.ipType, t.layerType, t.src, strconv.Itoa(int(t.srcPort)), t.dst, strconv.Itoa(int(t.dstPort))).Add(float64(t.len))
		}
	}
}

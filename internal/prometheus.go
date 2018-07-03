package internal

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var trafficSummary = prometheus.NewSummaryVec(
	prometheus.SummaryOpts{
		Name: "network_traffic",
		Help: "Network connections, partitioned by IP4/6, protocol (TCP/UDP), and source/destination",
		Objectives: map[float64]float64{},
	},
	[]string{"network_layer", "transport_layer", "source", "source_port", "destination", "destination_port"},
)

func init() {
	prometheus.MustRegister(trafficSummary)
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

		trafficSummary.WithLabelValues(t.ipType, t.layerType, t.src, strconv.Itoa(int(t.srcPort)), t.dst, strconv.Itoa(int(t.dstPort))).Observe(float64(t.len))
	}
}

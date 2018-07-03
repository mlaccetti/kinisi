package internal

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var trafficCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_traffic",
		Help: "Network connections, partitioned by IP4/6, protocol (TCP/UDP), and source/destination",
	},
	[]string{"network_layer", "transport_layer", "source", "destination"},
)

func init() {
	prometheus.MustRegister(trafficCounter)
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

		trafficCounter.WithLabelValues(t.ipType, t.layerType, t.src, t.dst + ":" + t.dstPort).Add(float64(t.len))
	}
}

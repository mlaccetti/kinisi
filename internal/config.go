package internal

import (
	"bytes"
	"flag"
	"os"
	"text/template"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type HelpTemplate struct {
	Flags string
}

const helpTemplate = `
Usage:
  kinisi [OPTIONS]

Application Options:
{{.Flags}}
Help Options:
  -h, --help                    Show this help message
`

var buf = new(bytes.Buffer)

func init() {
	pflag.BoolP("help", "h", false, "Show this help message")
	pflag.BoolP("verbose", "v", false, "Verbose output (default false)")
	pflag.BoolP("resolve_dns", "d", false, "Resolve IPs to names (default false)")
	pflag.StringP("interface", "i", "eth0", "Interface to read packets from")
	pflag.IntP("snaplen", "s", 65536, "Snap length (number of bytes max to read per packet)")
	pflag.StringP("filter", "f", "","BPF filter for pcap")
	pflag.IntP("connection_max_buffer", "c", 0, "Max packets to buffer for a single connection; 0 or less is infinity")
	pflag.IntP("total_max_buffer", "t", 0, "Max packets total to buffer; 0 or less is infinity")
	pflag.StringP("flush_after", "a", "60s", "Flush gaps in buffered packets for a connection after they hit a specific age")
	pflag.IntP("packet_count", "p", -1, "Quit after processing this many packets, negative means infinity")
}

func Config() (*viper.Viper) {
	v := viper.New()

	pflag.CommandLine.SortFlags = false
	pflag.CommandLine.MarkHidden("help")
	pflag.CommandLine.SetOutput(buf)

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	v.BindPFlags(pflag.CommandLine)

	v.AutomaticEnv()

	return v
}

func PrintHelp() {
	pflag.CommandLine.PrintDefaults()
	data := HelpTemplate{buf.String()}
	buf = new(bytes.Buffer)

	t := template.Must(template.New("help").Parse(helpTemplate))
	t.Execute(os.Stdout, data)
}

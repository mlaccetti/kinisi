package internal

import (
	"bytes"
	"flag"
	"os"
	"text/template"

	"github.com/google/gopacket/pfring"
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
	pflag.StringP("interface", "i", "eth0", "Interface to read packets from")
	pflag.IntP("snaplen", "s", 65536, "Snap length (number of bytes max to read per packet)")
	pflag.IntP("cluster", "c", -1, "If >= 0, sets the pfring cluster to this value")
	pflag.IntP("clustertype", "t", int(pfring.ClusterPerFlow), "cluster type")
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
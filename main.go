package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	"github.com/sensu/dns-check/internal/resolver"
	"github.com/sensu/dns-check/internal/transformer"
	"github.com/sensu/sensu-go/types"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	Domains            []string
	Servers            []string
	Class              string
	Type               string
	Port               string
	ValidateDNSSEC     bool
	InsecureStatus     int
	ValidateResolution bool
	UnresolvedStatus   int

	TCP            bool
	DefaultMsgSize uint16
}

var (
	cfg = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "dns-check",
			Short:    "DNS Check",
			Keyspace: "sensu.io/plugins/dns-check/config",
		},
		DefaultMsgSize: dns.DefaultMsgSize,
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "domain",
			Env:       "DOMAIN",
			Argument:  "domain",
			Shorthand: "d",
			Usage:     "Comma delimited list of domains",
			Value:     &cfg.Domains,
		}, {
			Path:      "server",
			Env:       "SERVER",
			Argument:  "server",
			Shorthand: "s",
			Usage:     "Comma delimited list DNS servers to query",
			Value:     &cfg.Servers,
		}, {
			Path:      "class",
			Env:       "CLASS",
			Argument:  "class",
			Shorthand: "c",
			Default:   "IN",
			Usage:     "Record Class to query",
			Value:     &cfg.Class,
		}, {
			Path:      "type",
			Env:       "TYPE",
			Argument:  "type",
			Shorthand: "t",
			Default:   "A",
			Usage:     "Record Type to query",
			Value:     &cfg.Type,
		}, {
			Path:      "port",
			Env:       "PORT",
			Argument:  "port",
			Shorthand: "p",
			Default:   "53",
			Usage:     "DNS server port",
			Value:     &cfg.Port,
		}, {
			Path:     "validate-resolution",
			Env:      "VALIDATE_RESOLUTION",
			Argument: "validate-resolution",
			Usage:    "exits with unresolved-status if any domain entries are unresolved",
			Value:    &cfg.ValidateResolution,
		}, {
			Path:     "unresolved-status",
			Env:      "UNRESOLVED_STATUS",
			Argument: "unresolved-status",
			Default:  1,
			Usage:    "exits with unresolved-status when validate-resolution is set",
			Value:    &cfg.UnresolvedStatus,
		}, {
			Path:     "validate-dnssec",
			Env:      "VALIDATE_DNSSEC",
			Argument: "validate-dnssec",
			Usage:    "exits with insecure-status when server indicates it was unable to validate dnssec signatures for records",
			Value:    &cfg.ValidateDNSSEC,
		}, {
			Path:     "insecure-status",
			Env:      "INSECURE_STATUS",
			Argument: "insecure-status",
			Default:  1,
			Usage:    "exits with insecure-status when validate-dnssec is set",
			Value:    &cfg.InsecureStatus,
		}, {
			Path:     "tcp",
			Env:      "TCP",
			Argument: "tcp",
			Default:  false,
			Usage:    "uses TCP connections to servers instead of UDP",
			Value:    &cfg.TCP,
		},
	}
)

func main() {
	useStdin := false
	fi, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("Error check stdin: %v\n", err)
		panic(err)
	}
	//Check the Mode bitmask for Named Pipe to indicate stdin is connected
	if fi.Mode()&os.ModeNamedPipe != 0 {
		log.Println("using stdin")
		useStdin = true
	}

	check := sensu.NewGoCheck(&cfg.PluginConfig, options, checkArgs, executeCheck, useStdin)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
	if len(cfg.Domains) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("must supply at least one domain to check")
	}
	var invalid []string
	for _, domain := range cfg.Domains {
		if _, ok := dns.IsDomainName(domain); !ok {
			invalid = append(invalid, domain)
		}
	}
	if len(invalid) > 0 {
		return sensu.CheckStateWarning, fmt.Errorf("invalid domain names specified: %s", invalid)
	}
	if len(cfg.Servers) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("must supply at least one name server")
	}
	if _, ok := dns.StringToType[strings.ToUpper(cfg.Type)]; !ok {
		return sensu.CheckStateWarning, fmt.Errorf("invalid record type: %s", cfg.Type)
	}
	if _, ok := dns.StringToClass[strings.ToUpper(cfg.Class)]; !ok {
		return sensu.CheckStateWarning, fmt.Errorf("invalid record class: %s", cfg.Class)
	}
	if port, err := strconv.Atoi(cfg.Port); err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("port must be numeric: %s", cfg.Port)
	} else if port < 1 {
		return sensu.CheckStateWarning, fmt.Errorf("invalid port number: %s", cfg.Port)
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *types.Event) (int, error) {
	var net string
	if cfg.TCP {
		net = "tcp"
	}
	resolv := resolver.Resolver{
		Class:          dns.StringToClass[strings.ToUpper(cfg.Class)],
		Type:           dns.StringToType[strings.ToUpper(cfg.Type)],
		Port:           cfg.Port,
		DefaultMsgSize: dns.DefaultMsgSize,
		Exchangeor: &dns.Client{
			Net: net,
		},
	}
	points := len(cfg.Domains) * len(cfg.Servers)
	results := make(chan metricsResult, points)
	for _, domain := range cfg.Domains {
		for _, nameServer := range cfg.Servers {
			go func(domain, server string, r chan<- metricsResult) {
				ts := time.Now().UnixNano()
				rtt, dnssec, err := resolv.Resolve(domain, server)

				var result metricsResult
				if cfg.ValidateDNSSEC && !dnssec {
					result.Code = cfg.InsecureStatus
				}
				if cfg.ValidateResolution && err != nil {
					result.Code = cfg.UnresolvedStatus
				}

				var resolved float64
				if err != nil {
					resolved = 1
				}
				var secure float64
				if !dnssec {
					secure = 1
				}

				tags := []*types.MetricTag{
					{
						Name:  "servername",
						Value: server,
					},
					{
						Name:  "domain",
						Value: domain,
					},
					{
						Name:  "record_class",
						Value: strings.ToUpper(cfg.Class),
					},
					{
						Name:  "record_type",
						Value: strings.ToUpper(cfg.Type),
					},
				}
				metrics := []types.MetricPoint{
					{
						Name:      "dns_resolved",
						Value:     resolved,
						Timestamp: ts,
						Tags:      append([]*types.MetricTag{{Name: transformer.AnnotationHelp, Value: "binary result 0 when the query can be resolved, otherwise 1"}}, tags...),
					},
					{
						Name:      "dns_response_time",
						Value:     float64(rtt) * 1e-9,
						Timestamp: ts,
						Tags:      append([]*types.MetricTag{{Name: transformer.AnnotationHelp, Value: "round trip response time to resolve the query in seconds"}}, tags...),
					}, {
						Name:      "dns_secure",
						Value:     secure,
						Timestamp: ts,
						Tags:      append([]*types.MetricTag{{Name: transformer.AnnotationHelp, Value: "binary result 0 when the server indicates dnssec signatures were validated, otherwise 1"}}, tags...),
					},
				}

				result.Metrics = metrics
				r <- result
			}(domain, nameServer, results)
		}
	}

	var metrics []types.MetricPoint
	var checkStatus int
	for i := 0; i < points; i++ {
		rs := <-results
		// exit with the largest exit code
		if rs.Code > checkStatus {
			checkStatus = rs.Code
		}
		metrics = append(metrics, rs.Metrics...)
	}
	fmt.Println(transformer.ToPrometheus(metrics))

	return checkStatus, nil
}

// metricsResult set of metrics from dns check and optional return code
type metricsResult struct {
	Metrics []types.MetricPoint
	Code    int
}

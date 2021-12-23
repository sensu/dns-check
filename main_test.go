package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/common/expfmt"
	"github.com/sensu/dns-check/internal/transformer"
	"github.com/sensu/sensu-plugin-sdk/sensu"
	"github.com/stretchr/testify/assert"
)

func TestCheckArgs(t *testing.T) {
	assert := assert.New(t)
	plugin.Servers = []string{"8.8.8.8", "8.8.4.4"}
	plugin.Domains = []string{"google.com"}
	plugin.Class = "IN"
	plugin.Type = "A"
	plugin.Port = "53"
	state, err := checkArgs(nil)
	assert.NoError(err)
	assert.Equal(sensu.CheckStateOK, state)
}

func TestCollectMetrics(t *testing.T) {
	// Setup asserter
	assert := assert.New(t)

	// Setup default values for plugin configuration
	plugin.Servers = []string{"8.8.8.8", "8.8.4.4"}
	plugin.Domains = []string{"google.com"}
	plugin.Class = "IN"
	plugin.Type = "A"
	plugin.Port = "53"

	// Run the plugin, validate that it collected metrics without errors
	metrics, checkStatus, _ := collectMetrics()
	assert.Equal(checkStatus, 0)

	// Check that output contains the expected metrics/tags
	output := transformer.ToPrometheus(metrics)
	assert.Contains(output, `dns_resolved{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"}`)
	assert.Contains(output, `dns_resolved{servername="8.8.4.4", domain="google.com", record_class="IN", record_type="A"}`)
	assert.Contains(output, `dns_response_time{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"}`)
	assert.Contains(output, `dns_response_time{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"}`)
	assert.Contains(output, `dns_secure{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"}`)
	assert.Contains(output, `dns_secure{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"}`)

	// Check that metrics are parsable
	var parser expfmt.TextParser
	parsedMetrics, err := parser.TextToMetricFamilies(strings.NewReader(output + "\n"))
	assert.NoError(err)

	// Check that every metric has a HELP and TYPE line
	for i := range parsedMetrics {
		assert.NotNil(parsedMetrics[i].Help)
		assert.NotNil(parsedMetrics[i].Type)
	}
	fmt.Println(output)
}

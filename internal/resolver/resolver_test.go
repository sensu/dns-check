package resolver_test

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sensu/dns-check/internal/resolver"
)

func TestResolve(t *testing.T) {
	underTest := resolver.Resolver{
		Class: dns.ClassINET,
		Type:  dns.TypeA,
		Port:  "53",
		Exchangeor: &dns.Client{
			Timeout: time.Millisecond * 500,
		},
	}
	_, err := underTest.Resolve("www.google.com", "8.8.8.8")
	if err != nil {
		t.Errorf("unexpected error resolving google.com. Check `dig @8.8.8.8 www.google.com +dnssec`: %v", err)
	}
}

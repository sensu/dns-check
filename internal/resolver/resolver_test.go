package resolver_test

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sensu/dns-check/internal/resolver"
)

// TestResolve integration test relies on external services
func TestResolve(t *testing.T) {
	underTest := resolver.Resolver{
		Class: dns.ClassINET,
		Type:  dns.TypeA,
		Port:  "53",
		Exchangeor: &dns.Client{
			Timeout: time.Millisecond * 500,
		},
	}
	_, sec, err := underTest.Resolve("www.google.com", "8.8.8.8")
	if err != nil {
		t.Errorf("unexpected error resolving google.com. Check `dig @8.8.8.8 www.google.com +dnssec`: %v", err)
	}
	if sec == true {
		t.Error("unexpected dnssec flag true for google.com")
	}

	_, sec, err = underTest.Resolve("isc.org", "8.8.8.8")
	if err != nil {
		t.Errorf("unexpected error resolving isc.org. Check `dig @8.8.8.8 isc.org. +dnssec`: %v", err)
	}
	if sec == false {
		t.Error("expected dnssec flag true for isc.org")
	}
}

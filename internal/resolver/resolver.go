package resolver

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	Class uint16
	Type  uint16
	Port  string

	Exchangeor     MessageExchangeor
	DefaultMsgSize uint16
}

type MessageExchangeor interface {
	Exchange(m *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error)
}

// Resolve records for a given domain/server
// returns round trip time, a secure flag, and error
func (r Resolver) Resolve(domain, server string) (rtt time.Duration, secure bool, err error) {
	exchange := r.Exchangeor
	if exchange == nil {
		exchange = &dns.Client{}
	}
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			AuthenticatedData: true,
		},
	}
	// Add DNSSEC OK Extension
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	opt.SetDo(true)
	opt.SetUDPSize(4096)
	m.Extra = append(m.Extra, opt)

	m.SetQuestion(dns.Fqdn(domain), r.Type)
	m.Question[0].Qclass = r.Class

	resp, rtt, err := exchange.Exchange(m, net.JoinHostPort(server, r.Port))
	if err == nil && resp.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("records did not resolve: %v", resp)
	}
	return rtt, resp.AuthenticatedData, err
}

[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/sensu/dns-check)
![Go Test](https://github.com/sensu/dns-check/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/sensu/dns-check/workflows/goreleaser/badge.svg)

# DNS Check

## Overview
[DNS Check][1] is a [Sensu Metrics Check][2] for monitoring dns resolver performance and behavior.

### Output Metrics

| Name                  | Description   |
|-----------------------|---------------|
| dns_response_time      | Response time for a given dns query. |
| dns_resolved   | Binary signal returns 0 when the record can be resolved. Otherwise 1.  |
| dns_secure    | Binary signal returns 0 when the server response indicates that DNSSEC signatures have been validated for all records. Otherwise 1. |

## Usage examples

```
➜  dns-check -s "8.8.8.8,8.8.4.4" -d "google.com"
# HELP dns_resolved binary result 0 when the query can be resolved, otherwise 1
# TYPE dns_resolved gauge
dns_resolved{servername="8.8.4.4", domain="google.com", record_class="IN", record_type="A"} 0.000000 1638381834985
dns_resolved{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"} 0.000000 1638381834985
# HELP dns_response_time round trip response time to resolve the query
# TYPE dns_response_time gauge
dns_response_time{servername="8.8.4.4", domain="google.com", record_class="IN", record_type="A"} 0.010874 1638381834985
dns_response_time{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"} 0.011209 1638381834985
# HELP dns_secure binary result 0 when the server indicates dnssec signatures were validated, otherwise 1
# TYPE dns_secure gauge
dns_secure{servername="8.8.4.4", domain="google.com", record_class="IN", record_type="A"} 1.000000 1638381834985
dns_secure{servername="8.8.8.8", domain="google.com", record_class="IN", record_type="A"} 1.000000 1638381834985
```

[1]: https://github.com/sensu/dns-check
[2]: https://docs.sensu.io/sensu-go/latest/observability-pipeline/observe-schedule/checks/
# kinisi

kubernetes traffic

## Developing

Filter out DNS queries to CloudFlare:

```bash
go run cmd/main.go -v -d -f "port not 53 and not arp"
```

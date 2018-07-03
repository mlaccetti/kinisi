# kinisi

kubernetes traffic

## Developing

Filter out DNS queries to CloudFlare:

```bash
go run cmd/main.go -v -d -f "not (src host 1.1.1.1 or 1.0.0.1) and not (dst host 1.1.1.1 or 1.0.0.1)"
```

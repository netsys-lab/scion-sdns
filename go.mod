module github.com/semihalev/sdns

require (
	github.com/BurntSushi/toml v1.0.0
	github.com/cespare/xxhash/v2 v2.1.2
	github.com/d4l3k/messagediff v1.2.1 // indirect
	github.com/gin-contrib/cors v1.3.1
	github.com/gin-contrib/pprof v1.3.0
	github.com/gin-gonic/gin v1.7.7
	github.com/miekg/dns v1.1.34
	github.com/netsec-ethz/scion-apps v0.5.0
	github.com/netsys-lab/sqnet v0.1.0
	github.com/prometheus/client_golang v1.12.1
	github.com/semihalev/log v0.1.1
	github.com/stretchr/testify v1.7.0
	github.com/yl2chen/cidranger v1.0.2
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
)

replace github.com/miekg/dns v1.1.34 => github.com/loujie1/dns v1.1.51

go 1.13

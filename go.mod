module github.com/KOMKZ/go-yogan-domain-auth

go 1.24.1

require (
	github.com/samber/do/v2 v2.0.0
	golang.org/x/crypto v0.46.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/samber/go-type-to-string v1.8.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gorm.io/gorm v1.31.1 // indirect
)

require (
	github.com/KOMKZ/go-yogan-framework v0.0.0
	go.uber.org/zap v1.27.1
)

replace github.com/KOMKZ/go-yogan-framework => ../../go-yogan-framework

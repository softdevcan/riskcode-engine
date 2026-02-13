module github.com/example/testproject

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/lib/pq v1.10.9
	github.com/stretchr/testify v1.8.4 // indirect
	golang.org/x/crypto v0.17.0
)

require (
	github.com/go-playground/validator/v10 v10.16.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.1 // indirect
)

replace github.com/lib/pq => github.com/jackc/pgx/v5 v5.5.0

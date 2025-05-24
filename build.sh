 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gateway
 docker build -t gateway .
 docker save gateway > gatewayDocker
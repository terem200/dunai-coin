.PHONY: default xbuild ybuild
default: xbuild ybuild
# Self-written part
xbuild: node.go client.go gclient.go serve.go values.go
	go build -o node node.go serve.go values.go
	go build -o client client.go values.go
	go build -o gclient gclient.go values.go

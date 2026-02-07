.PHONY: generate
generate: openapi
	go tool controller-gen object paths="./api/..."
	go tool controller-gen crd:allowDangerousTypes=false output:crd:artifacts:config=config/crd/bases paths="./api/..."

.PHONY: openapi
openapi:
	go tool oapi-codegen -generate types -package controlapi -o internal/controlapi/models.go openapi/openapi.yaml

.PHONY: manifests
manifests:
	go tool controller-gen crd:allowDangerousTypes=false output:crd:artifacts:config=config/crd/bases paths="./api/..."

.PHONY: test
test:
	go test ./... -v

.PHONY: fmt
fmt:
	gofmt -w .
	golines -w .

.PHONY: vet
vet:
	go vet ./...

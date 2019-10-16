module github.com/terraform-providers/terraform-provider-fortios

require (
	git.hv.devk.de/awsplattform/swagger-fortios v0.0.4 // indirect
	github.com/aws/aws-sdk-go v1.19.49 // indirect
	github.com/fgtdev/fortios-sdk-go v1.0.1
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/terraform v0.12.2
	github.com/hashicorp/vault v1.0.1 // indirect
	github.com/keybase/go-crypto v0.0.0-20181127160227-255a5089e85a // indirect
	github.com/pierrec/lz4 v2.0.5+incompatible // indirect
	github.com/stoewer/go-strcase v1.0.2 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/terraform-providers/terraform-provider-random v2.0.0+incompatible // indirect
	golang.org/x/net v0.0.0-20191014212845-da9a3fd4c582 // indirect
	google.golang.org/api v0.6.0 // indirect
)

replace github.com/fgtdev/fortios-sdk-go v1.0.1 => ../fortios-sdk-go

go 1.13

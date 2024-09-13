# CBOMkit-theia

[![GitHub License](https://img.shields.io/github/license/IBM/cbomkit-theia)](https://opensource.org/licenses/Apache-2.0)

This repository contains CBOMkit-theia: a tool that detects cryptographic assets in container images as well as directories and generates [CBOM](https://cyclonedx.org/capabilities/cbom/).

> [!NOTE] 
> CBOMkit-theia is meant to run in conjunction with the [Sonar Cryptography Plugin](https://github.com/IBM/sonar-cryptography) by IBM Research.
> Is is part of [cbomkit](https://github.com/IBM/cbomkit) by IBM Research 

```
 ██████╗██████╗  ██████╗ ███╗   ███╗██╗  ██╗██╗████████╗████████╗██╗  ██╗███████╗██╗ █████╗ 
██╔════╝██╔══██╗██╔═══██╗████╗ ████║██║ ██╔╝██║╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║██╔══██╗
██║     ██████╔╝██║   ██║██╔████╔██║█████╔╝ ██║   ██║█████╗██║   ███████║█████╗  ██║███████║
██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔═██╗ ██║   ██║╚════╝██║   ██╔══██║██╔══╝  ██║██╔══██║
╚██████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██╗██║   ██║      ██║   ██║  ██║███████╗██║██║  ██║
 ╚═════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝ by IBM Research

CBOMkit-theia analyzes cryptographic assets in a container image or directory.
It is part of cbomkit (https://github.com/IBM/cbomkit) by IBM Research.

--> Disclaimer: CBOMkit-theia does *not* perform source code scanning <--
--> Use https://github.com/IBM/sonar-cryptography for source code scanning <--

Features
- Find certificates in your image/directory
- Find keys in your image/directory
- Find secrets in your image/directory
- Verify the executability of cryptographic assets in a CBOM (requires --bom to be set)
- Output: Enriched CBOM to stdout/console

Supported image/filesystem sources:
- local directory 
- local application with dockerfile (ready to be build)
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image from dockerhub registry
- image from singularity

Supported BOM formats (input & output):
- CycloneDXv1.6

Examples:
cbomkit-theia dir my/cool/directory
cbomkit-theia image get nginx
cbomkit-theia image build my/Dockerfile

Plugin Explanations:
> "certificates": Certificate File Plugin
Find x.509 certificates

> "javasecurity": java.security Plugin
Verify the executability of cryptographic assets from Java code
Adds a confidence level (0-100) to the CBOM components to show how likely it is that this component is actually executable

> "secrets": Secret Plugin
Find Secrets & Keys

Usage:
  cbomkit-theia [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dir         Analyze cryptographic assets in a directory
  help        Help about any command
  image       Analyze cryptographic assets in a container image

Flags:
  -b, --bom string        BOM file to be verified and enriched
      --config string     config file (default is $HOME/.cbomkit-theia.yaml)
  -h, --help              help for cbomkit-theia
  -p, --plugins strings   list of plugins to use (default [certificates,javasecurity,secrets])
      --schema string     BOM schema to validate the given BOM (default "provider/cyclonedx/bom-1.6.schema.json")

Use "cbomkit-theia [command] --help" for more information about a command.
```

## Prerequisites

- Go 
  - Version: `1.22.2` or up
- Docker Daemon (if using `cbomkit-theia image build`)
  - Recommended: Set the `DOCKER_HOST` environment variable (default: `unix:///var/run/docker.sock`) 
- Internet Connection: CBOMkit-theia builds and pulls docker images during runtime

Tested with the following Docker Engine Specs:
```text
Server: Docker Engine - Community
 Engine:
  Version:          27.1.1
  API version:      1.46 (minimum version 1.24)
  Go version:       go1.21.12
  Git commit:       cc13f95
  Built:            Tue Jul 23 20:00:07 2024
  OS/Arch:          linux/arm64
  Experimental:     false
 containerd:
  Version:          1.7.19
  GitCommit:        2bf793ef6dc9a18e00cb12efb64355c2c9d5eb41
 runc:
  Version:          1.7.19
  GitCommit:        v1.1.13-0-g58aa920
 docker-init:
  Version:          0.19.0
  GitCommit:        de40ad0
```

## Running

### Compiled

```shell
go mod download
go build
./cbomkit-theia [command] > enriched_CBOM.json
```

### Interpreted

```shell
go mod download
go run ./cbomkit-theia.go [command] > enriched_CBOM.json
```

## Development

### Plugins
  - `java.security` Configuration Plugin:
    - Searches the filessystem for the `java.security` file and reads the configuration
    - Reads the `jdk.tls.disabledAlgorithms` property and checks if any of the algorithms are used in the given CBOM
    - Based on the results, a confidence level (`confidence_level`) is assigned to the restricted (or not restricted) algorithms in the CBOM
      - A higher confidence level means that component is more likely to be executable
  - X.509 Certificate Plugin:
    - Searches the filesystem for X.509 certificates
    - Adds the certificates to the CBOM, as well as signature algorithms, public keys and public key algorithms
  - Secret Plugin:
    - Leverages [gitleaks](https://github.com/gitleaks/gitleaks) to find secrets and keys in the data source
    - Adds the secrets and keys to the CBOM

Additional plugins can be added by implementing the `Plugin` interface from [`ibm/cbomkit-theia/scanner/plugins`](./scanner/plugins/plugin.go#L41) and adding the plugins constructor to the `GetAllPluginConstructors` function in [`ibm/cbomkit-theia/scanner/scanner.go`](./scanner/scanner.go#L48): 

## Security Disclaimer
CBOMkit-theia performs several filesystem reads based on the user input and may print the contents of these files to the stderr console. Do not use this tools on untrusted input or provide the output to untrusted parties.
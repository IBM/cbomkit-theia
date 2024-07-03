# CICS (Container Image Cryptography Scanner)

--> **Work in Progress** <--

```
 ██████ ██  ██████ ███████ 
██      ██ ██      ██      
██      ██ ██      ███████ 
██      ██ ██           ██ 
 ██████ ██  ██████ ███████ by IBM Research

Container Image Cryptography Scanner (CICS) 
verifies a given CBOM based on the given image or directory

The input is analyzed for any configurations limiting 
the usage of cryptography. Using these findings, 
the given CBOM is updated and verified. Additionally, 
CICS adds new cryptographic assets to the CBOM. 

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
cics dir my/cool/directory --bom my/bom.json
cics image get nginx --bom my/bom.json
cics image build my/Dockerfile --bom my/bom.json

Usage:
  cics [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dir         Verify CBOM using a directory
  help        Help about any command
  image       Verify CBOM using a container image

Flags:
  -b, --bom string      BOM file to verify using the given data
      --config string   config file (default is $HOME/.cics.yaml)
  -h, --help            help for cics
      --schema string   BOM schema to validate the given BOM (default "provider/cyclonedx/bom-1.6.schema.json")

Use "cics [command] --help" for more information about a command.
```

## Plugins
  - `java.security` Configuration Plugin:
    - Searches the filessystem for the `java.security` file and reads the configuration
    - Reads the `jdk.tls.disabledAlgorithms` property and checks if any of the algorithms are used in the given CBOM
    - Based on the results, a confidence level is assigned to the restricted (or not restricted) algorithms in the CBOM
  - X.509 Certificate Plugin:
    - Searches the filesystem for X.509 certificates
    - Adds the certificates to the CBOM, as well as signature algorithms, public keys and public key algorithms

Additional plugins can be added by implementing the `Plugin` interface from `ibm/container_cryptography_scanner/scanner/plugins` and adding the plugin to the `plugins` list in the `Scanner` struct in `ibm/container_cryptography_scanner/scanner/scanner.go`: 

```go
scanner.configPlugins = []plugins.Plugin{
    &javasecurity.JavaSecurityPlugin{},
    &certificates.CertificatesPlugin{},
    &myplugin.MyPlugin{},
}
```

## Security Disclaimer
The CICS performs several filesystem reads based on the user input and may print the contents of these files to the stderr console. Do not use this tools on untrusted input or provide the output to untrusted parties.
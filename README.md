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

Supported Configurations:
  - `java.security` configuration
    - `jdk.tls.disabledAlgorithms`
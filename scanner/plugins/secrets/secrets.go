// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	bomdag "ibm/container-image-cryptography-scanner/scanner/bom-dag"
	pemutility "ibm/container-image-cryptography-scanner/scanner/pem-utility"
	"ibm/container-image-cryptography-scanner/scanner/plugins"
	"strings"

	"net/http"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func NewSecretsPlugin() (plugins.Plugin, error) {
	return &SecretsPlugin{}, nil
}

type SecretsPlugin struct{}

func (SecretsPlugin) GetName() string {
	return "Secret Plugin"
}

func (SecretsPlugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

type findingWithMetadata struct {
	report.Finding
	mime string
}

func (SecretsPlugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return err
	}

	findings := make([]findingWithMetadata, 0)

	// Detect findings
	fs.WalkDir(func(path string) error {
		raw, err := fs.ReadFile(path)
		if err != nil {
			return err
		}

		mime := strings.Split(http.DetectContentType(raw), ";")[0]
		if !strings.HasPrefix(mime, "text") {
			return nil // Skip
		}

		fragment := detect.Fragment{
			Raw:      string(raw),
			FilePath: path,
		}

		for _, finding := range detector.Detect(fragment) {
			findings = append(findings, findingWithMetadata{
				Finding: finding,
				mime:    mime,
			})
		}

		return nil
	})

	bomDag := bomdag.NewBomDAG()

	components := make([]cdx.Component, 0)

	// Create CDX Components
	for _, finding := range findings {
		currentComponents, err := finding.getComponents(fs)
		if err != nil {
			return err
		}
		components = append(components, currentComponents...)
	}

	// Create DAG
	for _, comp := range components {
		hash, err := bomDag.AddCDXComponent(comp)
		if err != nil {
			return err
		}
		bomDag.AddEdge(bomDag.Root, hash)
	}

	// DAG to components
	secretComponents, _, err := bomDag.GetCDXComponents()
	if err != nil {
		return err
	}

	// Write to real bom
	*bom.Components = append(*bom.Components, secretComponents...)

	return nil
}

func (finding findingWithMetadata) getComponents(fs filesystem.Filesystem) ([]cdx.Component, error) {
	switch finding.RuleID {
	case "private-key":
		fileContent, err := fs.ReadFile(finding.File)
		if err != nil {
			return []cdx.Component{}, err
		}
		blocks := pemutility.ParsePEMToBlocksWithTypeFilter(fileContent, pemutility.Filter{
			FilterType: pemutility.PEMTypeFilterTypeAllowlist,
			List:       []pemutility.PEMBlockType{pemutility.PEMBlockTypePrivateKey, pemutility.PEMBlockTypeECPrivateKey, pemutility.PEMBlockTypeRSAPrivateKey, pemutility.PEMBlockTypeOPENSSHPrivateKey},
		})

		// Fallback
		if len(blocks) == 0 {
			return []cdx.Component{finding.getGenericSecretComponent()}, nil
		}

		for block := range blocks {
			currentComponents, err := pemutility.GenerateComponentsFromKeyBlock(block)
			if err != nil {
				return []cdx.Component{}, err
			}

			for i := range currentComponents {
				if currentComponents[i].Description != "" {
					currentComponents[i].Description += "; "
				}
				currentComponents[i].Description += finding.Description
				currentComponents[i].MIMEType = finding.mime
				currentComponents[i].Evidence = &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{
							Location: finding.File,
							Line:     &finding.StartLine,
						},
					},
				}
			}

			return currentComponents, nil
		}
	}

	return []cdx.Component{finding.getGenericSecretComponent()}, nil
}

func (finding findingWithMetadata) getGenericSecretComponent() cdx.Component {
	return cdx.Component{
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		MIMEType:    finding.mime,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: getRelatedCryptoAssetTypeFromRuleID(finding.RuleID),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		},
	}
}

func getRelatedCryptoAssetTypeFromRuleID(id string) cdx.RelatedCryptoMaterialType {
	switch {
	case id == "private-key":
		return cdx.RelatedCryptoMaterialTypePrivateKey
	case strings.Contains(id, "token") || strings.Contains(id, "jwt"):
		return cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(id, "key"):
		return cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(id, "password"):
		return cdx.RelatedCryptoMaterialTypePassword
	default:
		return cdx.RelatedCryptoMaterialTypeUnknown
	}
}

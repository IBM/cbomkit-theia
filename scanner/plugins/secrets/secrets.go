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

type SecretsPlugin struct {
}

func (SecretsPlugin) GetName() string {
	return "Secret Plugin"
}

func (SecretsPlugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

func (SecretsPlugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	findings := make([]report.Finding, 0)
	detector, err := detect.NewDetectorDefaultConfig()

	if err != nil {
		return err
	}

	fs.WalkDir(func(path string) error {
		raw, err := fs.ReadFile(path)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(http.DetectContentType(raw), "text") {
			return nil // Skip
		}

		fragment := detect.Fragment{
			Raw:      string(raw),
			FilePath: path,
		}

		findings = append(findings, detector.Detect(fragment)...)

		return nil
	})

	bomDag := bomdag.NewBomDAG()

	components := make([]cdx.Component, 0)

	for _, finding := range findings {
		switch finding.RuleID {
		case "private-key":
			fileContent, err := fs.ReadFile(finding.File)
			if err != nil {
				return err
			}
			blocks := pemutility.ParsePEMToBlocksWithTypeFilter(fileContent, pemutility.Filter{
				FilterType: pemutility.PEMTypeFilterTypeAllowlist,
				List:       []pemutility.PEMBlockType{pemutility.PEMBlockTypePrivateKey, pemutility.PEMBlockTypeECPrivateKey, pemutility.PEMBlockTypeRSAPrivateKey},
			})

			for block := range blocks {
				currentComponents, err := pemutility.GenerateComponentsFromKeyBlock(block)
				if err != nil {
					return err
				}

				for i := range currentComponents {
					currentComponents[i].Evidence = &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: finding.File},
						},
					}
				}

				components = append(components, currentComponents...)
			}
		default:
			components = append(components, getGenericSecretComponent(finding))
		}
	}

	for _, comp := range components {
		hash, err := bomDag.AddCDXComponent(comp)
		if err != nil {
			return err
		}
		bomDag.AddEdge(bomDag.Root, hash)
	}

	secretComponents, _, err := bomDag.GetCDXComponents()

	bomDag.WriteToFile(fs.GetIdentifier())

	if err != nil {
		return err
	}

	*bom.Components = append(*bom.Components, secretComponents...)

	return nil
}

func getGenericSecretComponent(finding report.Finding) cdx.Component {
	return cdx.Component{
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
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

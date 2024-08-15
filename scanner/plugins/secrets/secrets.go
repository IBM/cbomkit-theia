package secrets

import (
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner/plugins"

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
		fragment := detect.Fragment{
			Raw:      string(raw),
			FilePath: path,
		}

		findings = append(findings, detector.Detect(fragment)...)

		return nil
	})

	for _, finding := range findings {
		*bom.Components = append(*bom.Components, cdx.Component{
			Name:        finding.RuleID,
			Description: finding.Description,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{},
			},
			Evidence: &cdx.Evidence{
				Occurrences: &[]cdx.EvidenceOccurrence{
					{
						Location: finding.File,
					},
				},
			},
		})
	}

	return nil
}

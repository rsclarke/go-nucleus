package nucleus

import (
	"context"
	"fmt"
	"net/http"
)

type DataSensitivity int
type Compliance int

const (
	Low      DataSensitivity = 2
	Moderate DataSensitivity = 5
	High     DataSensitivity = 7
	Critical DataSensitivity = 10

	No  Compliance = 5
	Yes Compliance = 10
)

type Asset struct {
	OperatingSystemVersion string                 `json:"operating_system_version"`
	OperatingSystemName    string                 `json:"operating_system_name"`
	InactiveDate           string                 `json:"asset_inactive_date"`
	DataSensitivityScore   DataSensitivity        `json:"asset_data_sensitivity_score"`
	ImageID                string                 `json:"image_id"`
	Users                  []string               `json:"asset_users"`
	Location               string                 `json:"asset_location"`
	Criticality            string                 `json:"asset_criticality"`
	Active                 bool                   `json:"active"`
	ImageDistro            string                 `json:"image_distro"`
	IPAddress              string                 `json:"ip_address"`
	Notes                  string                 `json:"asset_notes"`
	ID                     string                 `json:"asset_id"`
	Name                   string                 `json:"asset_name"`
	Groups                 []string               `json:"asset_groups"`
	ImageRepo              string                 `json:"image_repo"`
	Info                   map[string]interface{} `json:"asset_info"`
	URL                    string                 `json:"url"`
	DomainName             string                 `json:"domain_name"`
	ComplianceScore        Compliance             `json:"asset_compliance_score"`
	Type                   string                 `json:"asset_type"`
	MACAddress             string                 `json:"mac_address"`
	Decommissioned         bool                   `json:"decommed"`
	ParentHostID           string                 `json:"parent_host_id"`
	ImageTag               string                 `json:"image_tag"`
}

// GetAsset returns details on a specific project
func (s *ProjectsService) GetAsset(ctx context.Context, projectID string, assetID string) (*Asset, *http.Response, error) {
	u := fmt.Sprintf("projects/%v/assets/%v", projectID, assetID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	a := new(Asset)
	resp, err := s.client.Do(ctx, req, a)
	if err != nil {
		return nil, resp, err
	}

	return a, resp, nil
}

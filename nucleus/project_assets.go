package nucleus

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rsclarke/go-nucleus/nucleus/internal/util"
)

type DataSensitivity string
type Compliance string
type ExploitableFinding string

const (
	Low      DataSensitivity = "2"
	Moderate DataSensitivity = "5"
	High     DataSensitivity = "7"
	Critical DataSensitivity = "10"

	No  Compliance = "5"
	Yes Compliance = "10"

	NotExploitable         ExploitableFinding = "0"
	Exploitable            ExploitableFinding = "1"
	ManuallySetExploitable ExploitableFinding = "2"
)

// Asset contains the property which describes an asset.
type Asset struct {
	OperatingSystemVersion string                 `json:"operating_system_version"`
	OperatingSystemName    string                 `json:"operating_system_name"`
	InactiveDate           string                 `json:"asset_inactive_date"`
	DataSensitivityScore   DataSensitivity        `json:"asset_data_sensitivity_score"`
	ImageID                string                 `json:"image_id"`
	Users                  []string               `json:"asset_users"`
	Location               string                 `json:"asset_location"`
	Criticality            string                 `json:"asset_criticality"`
	CriticalityScore       string                 `json:"asset_criticality_score"`
	Active                 bool                   `json:"active"`
	ImageDistro            string                 `json:"image_distro"`
	IPAddress              string                 `json:"ip_address"`
	Notes                  string                 `json:"asset_notes"`
	ID                     string                 `json:"asset_id,omitempty"`
	Name                   string                 `json:"asset_name"`
	MatchName              string                 `json:"asset_match_name"`      // not in swagger
	MatchNameLink          string                 `json:"asset_match_name_link"` // not in swagger
	Groups                 util.EmptyStrAsSlice   `json:"asset_groups"`          // GetAsset returns the empty string "" for groups instead of the empty array
	ImageRepo              string                 `json:"image_repo"`
	Info                   map[string]interface{} `json:"asset_info"`
	URL                    string                 `json:"url"`
	DomainName             string                 `json:"domain_name"`
	ComplianceScore        Compliance             `json:"asset_complianced_score"`
	Type                   string                 `json:"asset_type"`
	MACAddress             string                 `json:"mac_address"`
	Decommissioned         string                 `json:"decommed"`
	ParentHostID           string                 `json:"parent_host_id"`
	ImageTag               string                 `json:"image_tag"`
}

// AssetVuln includes asset and vulnerability information (not as detailed as Asset)
// There is a fair amount of duplication here which needs to be tidied up.
type AssetVuln struct {
	ID                        string             `json:"asset_id"`
	Name                      string             `json:"asset_name"`
	IPAddress                 string             `json:"ip_address"`
	Groups                    []string           `json:"asset_groups"`
	Type                      string             `json:"asset_type"`
	ScanDate                  string             `json:"scan_date"`
	Info                      util.EmptyStrAsMap `json:"asset_info"` // ListAssets returns the ass info as empty string instead of empty array
	ScanDateTimestmap         int64              `json:"scan_date_timestamp"`
	OperatingSystemName       string             `json:"operating_system_name"`
	MACAddress                string             `json:"mac_address"`
	FindingCountCritical      string             `json:"finding_count_critical"`
	FindingCountHigh          string             `json:"finding_count_high"`
	FindingCountMedium        string             `json:"finding_count_medium"`
	FindingCountLow           string             `json:"finding_count_low"`
	FindingCountInformational string             `json:"finding_count_informational"`
	FindingCountPass          string             `json:"finding_count_pass"`
	FindingCountFail          string             `json:"finding_count_fail"`
	FindingVulnerabilityScore string             `json:"finding_vulnerability_score"`
	Public                    string             `json:"asset_public"`
	Criticality               string             `json:"asset_criticality"`
	DataSensitivityScore      DataSensitivity    `json:"asset_data_sensitivity_score"`
	ComplianceScore           Compliance         `json:"asset_complianced_score"`
	CriticalityScore          string             `json:"asset_criticality_score"`
	InactiveDate              string             `json:"asset_inactive_date"`
	ImageID                   string             `json:"image_id"`
	ImageDistro               string             `json:"image_distro"`
	ImageRepo                 string             `json:"image_repo"`
	ImageTag                  string             `json:"image_tag"`
	Active                    bool               `json:"active"`
}

type FindingSummaryRecord struct {
	AssetFixedCount      int64                `json:"asset_fixed_count"`
	AssetMitigatedCount  int64                `json:"asset_mitigated_count"`
	AssetCount           string               `json:"asset_count"`
	Name                 string               `json:"finding_name"`
	Number               string               `json:"finding_number"`
	Discovered           string               `json:"finding_discovered"`
	Exploitable          ExploitableFinding   `json:"finding_exploitable"`
	Result               string               `json:"finding_result"`
	Severity             string               `json:"finding_severity"`
	Status               string               `json:"finding_status"`
	CVE                  string               `json:"finding_cve"`
	Count                string               `json:"finding_count"`
	IAVA                 string               `json:"finding_iava"`
	ScanDate             string               `json:"scan_date"`
	ScanType             string               `json:"scan_type"`
	IssueOpenCount       int64                `json:"issue_open_count"`
	IssueClosedCount     int64                `json:"issue_closed_count"`
	Issues               util.EmptyStrAsSlice `json:"issues"`
	ComplianceFrameworks []struct {
		Name string `json:"framework_name"`
	} `json:"compliance_frameworks"`
}

type AssetGroup struct {
	Name string `json:"asset_group"`
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

type ListAssetsRequest struct {
	Start          int64
	Limit          int64
	IPAddress      string
	AssetName      string
	AssetNameOrIP  string
	AssetGroups    []string
	InactiveAssets bool
}

func (s *ProjectsService) ListAssets(ctx context.Context, projectID string, request ListAssetsRequest) ([]*AssetVuln, *http.Response, error) {
	u := fmt.Sprintf("projects/%v/assets", projectID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	q := req.URL.Query()
	if request.Start > 0 {
		q.Add("start", strconv.FormatInt(request.Start, 10))
	}
	if request.Limit > 0 {
		q.Add("limit", strconv.FormatInt(request.Limit, 10))
	}
	if request.IPAddress != "" {
		q.Add("ip_address", request.IPAddress)
	}
	if request.AssetName != "" {
		q.Add("asset_name", request.AssetName)
	}
	if request.AssetNameOrIP != "" {
		q.Add("asset_name_ip", request.AssetNameOrIP)
	}
	if request.InactiveAssets {
		q.Add("inactive_assets", strconv.FormatBool(request.InactiveAssets))
	}

	req.URL.RawQuery = q.Encode()

	var a []*AssetVuln
	resp, err := s.client.Do(ctx, req, &a)
	if err != nil {
		return nil, resp, err
	}

	return a, resp, nil
}

func (s *ProjectsService) ListAssetFindings(ctx context.Context, projectID string, assetID string) ([]*FindingSummaryRecord, *http.Response, error) {
	u := fmt.Sprintf("projects/%v/assets/%v/findings", projectID, assetID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var r []*FindingSummaryRecord
	resp, err := s.client.Do(ctx, req, &r)
	if err != nil {
		return nil, resp, err
	}

	return r, resp, nil
}

func (s *ProjectsService) ListAssetGroups(ctx context.Context, projectID string) ([]*AssetGroup, *http.Response, error) {
	u := fmt.Sprintf("projects/%v/assets/groups", projectID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var g []*AssetGroup
	resp, err := s.client.Do(ctx, req, &g)
	if err != nil {
		return nil, resp, err
	}

	return g, resp, nil
}

type UpdateAssetResponse struct {
	AssetID       string   `json:"asset_id"`
	UnknownFields []string `json:"unknown_fields"`
	Success       bool     `json:"success"`
}

func (s *ProjectsService) UpdateAsset(ctx context.Context, projectID string, asset *Asset) (*UpdateAssetResponse, *http.Response, error) {
	assetID := asset.ID
	trimAsset := *asset
	trimAsset.ID = ""

	u := fmt.Sprintf("projects/%v/assets/%v", projectID, assetID)
	req, err := s.client.NewRequest("PUT", u, trimAsset)
	if err != nil {
		return nil, nil, err
	}

	r := new(UpdateAssetResponse)
	resp, err := s.client.Do(ctx, req, &r)
	if err != nil {
		return nil, resp, err
	}

	return r, resp, nil
}

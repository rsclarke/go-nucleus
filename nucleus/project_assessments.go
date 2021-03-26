package nucleus

import (
	"context"
	"fmt"
	"net/http"
)

// AssessmentContact contains the contact details of the assessor
type AssessmentContact struct {
	Email string `json:"contact_email"`
	Name  string `json:"contact_name"`
	Role  string `json:"contact_role"`
	Phone string `json:"contact_phone"`
	Title string `json:"contact_title"`
}

// AssessmentVuln scores
type AssessmentVuln struct {
	UM int `json:"uM"`
	UL int `json:"uL"`
	TL int `json:"tL"`
	TM int `json:"tM"`
	UI int `json:"uI"`
	UH int `json:"uH"`
	TH int `json:"tH"`
	TI int `json:"tI"`
	UE int `json:"uE"`
	TE int `json:"tE"`
	TC int `json:"tC"`
	UC int `json:"uC"`
}

// AssessmentActivity actions conducted by users
type AssessmentActivity struct {
	Action string `json:"action"`
	Date   int64  `json:"date"`
	User   string `json:"user"`
}

// AssessmentData contains the results of an assessment
type AssessmentData struct {
	Contacts           []AssessmentContact  `json:"assessment_contacts"`
	End                string               `json:"assessment_end"`
	ReportLimitations  string               `json:"assessment_report_limitations"`
	ReportOverview     string               `json:"assessment_report_overview"`
	ProviderName       string               `json:"assessment_provider_name"`
	Vulns              AssessmentVuln       `json:"vulns"`
	Type               string               `json:"assessment_type"`
	Provider           string               `json:"assessment_provider"`
	AssessmentActivity []AssessmentActivity `json:"assessment_activity"`
	ReportIntro        string               `json:"assessment_report_intro"`
	Environment        string               `json:"assessment_environment"`
	Scope              string               `json:"assessment_scope"`
	Status             string               `json:"assessment_status"`
	Start              string               `json:"assessment_start"`
}

// Assessment a conducted assessment of the project
type Assessment struct {
	ProjectID       string         `json:"project_id"`
	Data            AssessmentData `json:"assessment_data"`
	ParentProjectID string         `json:"parent_project_id"`
	Name            string         `json:"assessment_name"`
}

// ListAssessments returns all assessments for a given project id
func (s *ProjectsService) ListAssessments(ctx context.Context, projectID string) ([]*Assessment, *http.Response, error) {
	u := fmt.Sprintf("projects/%v/assessments", projectID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var a []*Assessment
	resp, err := s.client.Do(ctx, req, &a)
	if err != nil {
		return nil, resp, err
	}

	return a, resp, nil
}

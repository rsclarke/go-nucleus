package nucleus

import (
	"context"
	"fmt"
	"net/http"
)

// ProjectsService provides access to project related functions
type ProjectsService service

// Project holds the metadata
type Project struct {
	TrackingMethod string   `json:"tracking_method"`
	Name           string   `json:"project_name"`
	Description    string   `json:"project_description"`
	ID             string   `json:"project_id"` // API returns string not int64
	Groups         []string `json:"project_groups"`
	Org            string   `json:"project_org"`
}

// ListProjects returns a list of all projects with the current status
func (s *ProjectsService) ListProjects(ctx context.Context) ([]*Project, *http.Response, error) {
	req, err := s.client.NewRequest("GET", "projects", nil)
	if err != nil {
		return nil, nil, err
	}

	var p []*Project
	resp, err := s.client.Do(ctx, req, &p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, nil
}

// GetProject returns details on a specific project
func (s *ProjectsService) GetProject(ctx context.Context, id int64) (*Project, *http.Response, error) {
	u := fmt.Sprintf("projects/%v", id)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	p := new(Project)
	resp, err := s.client.Do(ctx, req, p)
	if err != nil {
		return nil, resp, err
	}

	return p, resp, nil
}

package nucleus

import (
	"context"
	"fmt"
	"net/http"
)

type Connector struct {
	ID          string                   `json:"connector_id"`
	Type        string                   `json:"connector_type"`
	Name        string                   `json:"connector_name"`
	Description string                   `json:"connector_description"`
	Fields      []map[string]interface{} `json:"connector_fields"`
}

// ListProjects returns a list of all projects with the current status
func (s *ProjectsService) ListConnectors(ctx context.Context, projectID string) ([]*Connector, *http.Response, error) {
	u := fmt.Sprintf("projects/%v/connectors", projectID)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var c []*Connector
	resp, err := s.client.Do(ctx, req, &c)
	if err != nil {
		return nil, resp, err
	}

	return c, resp, nil
}

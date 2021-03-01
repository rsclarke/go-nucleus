package nucleus

import (
	"context"
	"net/http"
	"strconv"
)

// LogsService provides access to audit log related functions
type LogsService service

// Log represents an entry in the audit log
type Log struct {
	Details  string `json:"details"`
	Datetime string `json:"datetime"`
}

// LogRequest options to limit requested audit log events
type LogRequest struct {
	Start int64
	Limit int64
	After string
	Since int64
}

// GetAuditLogs returns log events for the given time period given in the logRequest
func (s *LogsService) GetAuditLogs(ctx context.Context, logRequest LogRequest) ([]*Log, *http.Response, error) {
	req, err := s.client.NewRequest("GET", "logs", nil)
	if err != nil {
		return nil, nil, err
	}

	q := req.URL.Query()
	q.Add("start", strconv.FormatInt(logRequest.Start, 10))
	q.Add("limit", strconv.FormatInt(logRequest.Limit, 10))

	if logRequest.After != "" {
		q.Add("after", logRequest.After)
	} else {
		q.Add("since", strconv.FormatInt(logRequest.Since, 10))
	}

	req.URL.RawQuery = q.Encode()

	var l []*Log
	resp, err := s.client.Do(ctx, req, &l)
	if err != nil {
		return nil, resp, err
	}

	return l, resp, nil
}

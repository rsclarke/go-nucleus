package util

import "encoding/json"

type EmptyStrAsSlice []string

func (slice *EmptyStrAsSlice) UnmarshalJSON(b []byte) error {
	// Try unmarshal as a string slice
	var values []string
	_ = json.Unmarshal(b, &values) // disregard the error
	*slice = values
	return nil
}

type EmptyStrAsMap map[string]interface{}

func (slice *EmptyStrAsMap) UnmarshalJSON(b []byte) error {
	var values map[string]interface{}
	_ = json.Unmarshal(b, &values)
	*slice = values
	return nil
}

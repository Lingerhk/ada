// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package entry

import (
	"fmt"
	"time"
)

var timeNow = time.Now

// Entry is a flexible representation of log data associated with a timestamp.
type Entry struct {
	Timestamp  int64          `json:"timestamp"               yaml:"timestamp"` // collect time
	EventTime  int64          `json:"EventTime"               yaml:"EventTime"` // event create time
	Body       any            `json:"body"                    yaml:"body"`
	Attributes map[string]any `json:"attributes,omitempty"    yaml:"attributes,omitempty"`
}

// New will create a new log entry with current timestamp and an empty body.
func New() *Entry {
	return &Entry{
		Timestamp: timeNow().UnixMilli(), // 13-digit ms timestamp
	}
}

// AddAttribute will add a key/value pair to the entry's attributes.
func (entry *Entry) AddAttribute(key, value string) {
	if entry.Attributes == nil {
		entry.Attributes = make(map[string]any)
	}
	entry.Attributes[key] = value
}

// Get will return the value of a field on the entry, including a boolean indicating if the field exists.
func (entry *Entry) Get(field FieldInterface) (any, bool) {
	return field.Get(entry)
}

// Set will set the value of a field on the entry.
func (entry *Entry) Set(field FieldInterface, val any) error {
	return field.Set(entry, val)
}

// Delete will delete a field from the entry.
func (entry *Entry) Delete(field FieldInterface) (any, bool) {
	return field.Delete(entry)
}

// Read will read the value of a field into a designated interface.
func (entry *Entry) Read(field FieldInterface, dest any) error {
	switch dest := dest.(type) {
	case *string:
		return entry.readToString(field, dest)
	case *map[string]any:
		return entry.readToInterfaceMap(field, dest)
	case *map[string]string:
		return entry.readToStringMap(field, dest)
	case *any:
		return entry.readToInterface(field, dest)
	default:
		return fmt.Errorf("can not read to unsupported type '%T'", dest)
	}
}

// readToInterface reads a field to a designated interface pointer.
func (entry *Entry) readToInterface(field FieldInterface, dest *any) error {
	val, ok := entry.Get(field)
	if !ok {
		return fmt.Errorf("field '%s' is missing and can not be read as a any", field)
	}

	*dest = val
	return nil
}

// readToString reads a field to a designated string pointer.
func (entry *Entry) readToString(field FieldInterface, dest *string) error {
	val, ok := entry.Get(field)
	if !ok {
		return fmt.Errorf("field '%s' is missing and can not be read as a string", field)
	}

	switch typed := val.(type) {
	case string:
		*dest = typed
	case []byte:
		*dest = string(typed)
	default:
		return fmt.Errorf("field '%s' of type '%T' can not be cast to a string", field, val)
	}

	return nil
}

// readToInterfaceMap reads a field to a designated map interface pointer.
func (entry *Entry) readToInterfaceMap(field FieldInterface, dest *map[string]any) error {
	val, ok := entry.Get(field)
	if !ok {
		return fmt.Errorf("field '%s' is missing and can not be read as a map[string]any", field)
	}

	if m, ok := val.(map[string]any); ok {
		*dest = m
	} else {
		return fmt.Errorf("field '%s' of type '%T' can not be cast to a map[string]any", field, val)
	}

	return nil
}

// readToStringMap reads a field to a designated map string pointer.
func (entry *Entry) readToStringMap(field FieldInterface, dest *map[string]string) error {
	val, ok := entry.Get(field)
	if !ok {
		return fmt.Errorf("field '%s' is missing and can not be read as a map[string]string{}", field)
	}

	switch m := val.(type) {
	case map[string]any:
		newDest := make(map[string]string)
		for k, v := range m {
			vStr, ok := v.(string)
			if !ok {
				return fmt.Errorf("can not cast map members '%s' of type '%s' to string", k, v)
			}
			newDest[k] = vStr
		}
		*dest = newDest
	case map[any]any:
		newDest := make(map[string]string)
		for k, v := range m {
			keyStr, ok := k.(string)
			if !ok {
				return fmt.Errorf("can not cast map key of type '%T' to string", k)
			}
			vStr, ok := v.(string)
			if !ok {
				return fmt.Errorf("can not cast map value of type '%T' to string", v)
			}
			newDest[keyStr] = vStr
		}
		*dest = newDest
	}

	return nil
}

// Copy will return a deep copy of the entry.
func (entry *Entry) Copy() *Entry {
	return &Entry{
		Timestamp:  entry.Timestamp,
		EventTime:  entry.EventTime,
		Attributes: copyInterfaceMap(entry.Attributes),
		Body:       copyValue(entry.Body),
	}
}

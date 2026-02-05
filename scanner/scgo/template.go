package scgo

import (
	"fmt"
	"reflect"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func (s *Service) getTemplatePlugin(templateHex string, pluginID int32) (map[string]any, error) {
	id, err := bson.ObjectIDFromHex(templateHex)
	if err != nil {
		return nil, err
	}
	var tmpl bson.M
	err, exist := s.MongoCli.FindOne("tb_scan_template", bson.M{"_id": id}, &tmpl)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("template not found: %s", templateHex)
	}

	pluginsAny := tmpl["plugins"]
	if arr, ok := asSliceAny(pluginsAny); ok {
		for _, it := range arr {
			if p, ok := mapFromAny(it); ok {
				if hit, ok := matchPluginByID(p, pluginID); ok {
					return hit, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("plugin %d not found in template %s", pluginID, templateHex)
}

func matchPluginByID(p map[string]any, pluginID int32) (map[string]any, bool) {
	pid, ok := asInt32(p["_id"])
	if ok && pid == pluginID {
		return p, true
	}
	return nil, false
}

func mapFromAny(v any) (map[string]any, bool) {
	switch p0 := v.(type) {
	case map[string]any:
		return p0, true
	case bson.M:
		return map[string]any(p0), true
	case bson.D:
		return mapFromDoc(p0), true
	default:
		// fall through to reflection-based conversion
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, false
	}
	if rv.Kind() == reflect.Map {
		if rv.Type().Key().Kind() != reflect.String {
			return nil, false
		}
		out := make(map[string]any, rv.Len())
		for _, k := range rv.MapKeys() {
			out[k.String()] = rv.MapIndex(k).Interface()
		}
		return out, true
	}
	if rv.Kind() == reflect.Slice {
		if rv.Len() == 0 {
			return nil, false
		}
		elemType := rv.Type().Elem()
		if elemType.Kind() == reflect.Ptr {
			elemType = elemType.Elem()
		}
		if elemType.Kind() == reflect.Struct {
			keyField, okKey := elemType.FieldByName("Key")
			_, okVal := elemType.FieldByName("Value")
			if okKey && okVal && keyField.Type.Kind() == reflect.String {
				out := make(map[string]any, rv.Len())
				for i := 0; i < rv.Len(); i++ {
					e := rv.Index(i)
					if e.Kind() == reflect.Ptr {
						if e.IsNil() {
							continue
						}
						e = e.Elem()
					}
					k := e.FieldByName("Key").String()
					out[k] = e.FieldByName("Value").Interface()
				}
				return out, true
			}
		}
	}
	// last resort: try BSON round-trip into a map
	if b, err := bson.Marshal(v); err == nil {
		var m bson.M
		if err := bson.Unmarshal(b, &m); err == nil {
			return map[string]any(m), true
		}
	}
	return nil, false
}

func mapFromDoc(d bson.D) map[string]any {
	m := make(map[string]any, len(d))
	for _, e := range d {
		m[e.Key] = e.Value
	}
	return m
}

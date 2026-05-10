package scgo

import (
	"ada/infra/mongo"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type PluginEntry struct {
	ID          int32
	Category    string
	PluginDir   string
	Module      string // e.g. plugins.baseline.plugin_1001.main
	PackagePath string // .../package.json
	PackageDoc  map[string]any
}

type PluginIndex struct {
	ByID   map[int32]*PluginEntry
	AllIDs []int32
}

func BuildPluginIndex(scRoot string) (*PluginIndex, error) {
	pluginsRoot := filepath.Join(scRoot, "plugins")
	matches, err := filepath.Glob(filepath.Join(pluginsRoot, "*", "plugin_*", "package.json"))
	if err != nil {
		return nil, err
	}
	idx := &PluginIndex{ByID: map[int32]*PluginEntry{}}

	for _, pkgPath := range matches {
		mainSoPath := filepath.Join(filepath.Dir(pkgPath), "main.so")
		if st, err := os.Stat(mainSoPath); err != nil || st.IsDir() {
			logger.Debugf("skip uncompiled plugin package=%s missing main.so", pkgPath)
			continue
		}

		b, err := os.ReadFile(pkgPath)
		if err != nil {
			return nil, err
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", pkgPath, err)
		}

		id, ok := asInt32(doc["_id"])
		if !ok {
			return nil, fmt.Errorf("invalid plugin _id in %s: %T", pkgPath, doc["_id"])
		}
		doc["_id"] = id

		// plugins/<category>/<plugin_dir>/package.json
		pluginDir := filepath.Base(filepath.Dir(pkgPath))
		category := filepath.Base(filepath.Dir(filepath.Dir(pkgPath)))
		module := fmt.Sprintf("plugins.%s.%s.main", category, pluginDir)

		idx.ByID[id] = &PluginEntry{
			ID:          id,
			Category:    category,
			PluginDir:   pluginDir,
			Module:      module,
			PackagePath: pkgPath,
			PackageDoc:  doc,
		}
		idx.AllIDs = append(idx.AllIDs, id)
	}

	sort.Slice(idx.AllIDs, func(i, j int) bool { return idx.AllIDs[i] < idx.AllIDs[j] })
	return idx, nil
}

// RegisterPluginsAndTemplates refreshes scanner plugin metadata.
// It populates:
// - tb_scan_plugin
// - plugin lists on builtin templates seeded by MongoDB init
// - backfills missing builtin plugins into other templates (enable=0)
func RegisterPluginsAndTemplates(ctx context.Context, mgo mongo.DBAdaptor, idx *PluginIndex) error {
	// step 1 register plugins
	if err := mgo.Remove(ctx, "tb_scan_plugin", bson.M{}, true); err != nil {
		return err
	}

	builtin := map[string][]map[string]any{
		"baseline": {},
		"leak":     {},
		"weakpwd":  {},
	}

	for _, id := range idx.AllIDs {
		ent := idx.ByID[id]
		if ent == nil {
			continue
		}
		if err := mgo.Insert(ctx, "tb_scan_plugin", ent.PackageDoc); err != nil {
			return fmt.Errorf("insert plugin %d: %w", id, err)
		}
		if _, ok := builtin[ent.Category]; ok {
			builtin[ent.Category] = append(builtin[ent.Category], ent.PackageDoc)
		}
	}

	// step 2 refresh builtin templates seeded by MongoDB init
	baselineName := "Built-in Baseline Detection Template"
	leakName := "Built-in Vulnerability Detection Template"
	weakpwdName := "Built-in Weak Password Detection Template"

	now := time.Now().UTC()
	defTemplates := []struct {
		IDHex string
		Name  string
		Type  string
		Plugs []map[string]any
	}{
		{"6425b14857e6c3ceef50e461", baselineName, "baseline", builtin["baseline"]},
		{"6425b14857e6c3ceef50e462", leakName, "leak", builtin["leak"]},
		{"6425b14857e6c3ceef50e463", weakpwdName, "weakpwd", builtin["weakpwd"]},
	}

	for _, t := range defTemplates {
		id, err := bson.ObjectIDFromHex(t.IDHex)
		if err != nil {
			return err
		}
		doc := bson.M{
			"_id":       id,
			"name":      t.Name,
			"type":      t.Type,
			"plugins":   t.Plugs,
			"tmpl_type": int32(1),
			"create_tm": now,
			"update_tm": now,
		}
		update := bson.M{
			"name":      t.Name,
			"type":      t.Type,
			"plugins":   t.Plugs,
			"tmpl_type": int32(1),
			"update_tm": now,
		}
		var existing bson.M
		err, exist := mgo.FindOne(ctx, "tb_scan_template", bson.M{"_id": id}, &existing)
		if err != nil && err != mongo.ErrNotFound {
			return fmt.Errorf("find builtin template %s: %w", t.Name, err)
		}
		if exist {
			if err := mgo.UpdateById(ctx, "tb_scan_template", id, update); err != nil {
				return fmt.Errorf("update builtin template %s: %w", t.Name, err)
			}
			continue
		}
		if err := mgo.Insert(ctx, "tb_scan_template", doc); err != nil {
			return fmt.Errorf("insert builtin template %s: %w", t.Name, err)
		}
	}

	// step 3 update other templates: ensure all builtin plugins exist, missing ones appended with enable=0
	var others []bson.M
	if err := mgo.FindAll(ctx, "tb_scan_template", bson.M{"name": bson.M{"$nin": []string{baselineName, leakName, weakpwdName}}}, &others); err != nil {
		return err
	}

	builtinByType := map[string]map[int32]map[string]any{}
	for typ, arr := range builtin {
		m := map[int32]map[string]any{}
		for _, p := range arr {
			pid, ok := asInt32(p["_id"])
			if !ok {
				continue
			}
			m[pid] = p
		}
		builtinByType[typ] = m
	}

	for _, t := range others {
		idAny := t["_id"]
		id, ok := idAny.(bson.ObjectID)
		if !ok {
			// Some drivers decode as primitive.ObjectID; best-effort by string.
			logger.Warnf("skip template with unknown _id type: %T", idAny)
			continue
		}

		typ := asString(t["type"])
		bmap, ok := builtinByType[typ]
		if !ok {
			continue
		}

		// existing plugins
		pluginsAny := t["plugins"]
		var plugins []map[string]any
		switch vv := pluginsAny.(type) {
		case []map[string]any:
			plugins = vv
		case []bson.M:
			for _, x := range vv {
				plugins = append(plugins, map[string]any(x))
			}
		case []any:
			for _, it := range vv {
				switch p := it.(type) {
				case map[string]any:
					plugins = append(plugins, p)
				case bson.M:
					plugins = append(plugins, map[string]any(p))
				}
			}
		default:
			// no plugins field
		}

		existing := map[int32]bool{}
		for _, pm := range plugins {
			pid, ok := asInt32(pm["_id"])
			if ok {
				existing[pid] = true
			}
		}

		changed := false
		for pid, pdoc := range bmap {
			if existing[pid] {
				continue
			}
			// clone and disable
			clone := map[string]any{}
			for k, v := range pdoc {
				clone[k] = v
			}
			clone["enable"] = int32(0)
			plugins = append(plugins, clone)
			changed = true
		}
		if !changed {
			continue
		}

		// ensure stable order by _id
		sort.SliceStable(plugins, func(i, j int) bool {
			idi, _ := asInt32(plugins[i]["_id"])
			idj, _ := asInt32(plugins[j]["_id"])
			return idi < idj
		})

		upd := bson.M{"plugins": plugins, "update_tm": now}
		if err := mgo.UpdateById(ctx, "tb_scan_template", id, upd); err != nil {
			return fmt.Errorf("update template %s: %w", strings.TrimSpace(asString(t["name"])), err)
		}
	}

	logger.Infof("registered plugins=%d; templates refreshed", len(idx.AllIDs))
	return nil
}

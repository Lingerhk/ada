package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestAdvancedSearchCurrentThreatEventFields(t *testing.T) {
	got, err := AdvancedSearch([]AdvancedSearchReq{
		{Name: "title", Type: "eq", Value: []string{"flow-0005"}},
		{Name: "level", Type: "eq", Value: []string{"3", "4"}},
		{Name: "eventStatus", Type: "eq", Value: []string{"0"}},
		{Name: "time", Type: "bt", Value: []string{"2025-10-19 00:00:00", "2025-10-19 01:00:00"}},
	})
	require.NoError(t, err)

	startTime, endTime, err := initTimeInterval("2025-10-19 00:00:00", "2025-10-19 01:00:00")
	require.NoError(t, err)
	expected := bson.D{{Key: "$and", Value: bson.A{
		bson.D{{Key: "flow_id", Value: bson.D{{Key: "$in", Value: []string{"flow-0005"}}}}},
		bson.D{{Key: "level", Value: bson.D{{Key: "$in", Value: []int32{3, 4}}}}},
		bson.D{{Key: "event_status", Value: bson.D{{Key: "$in", Value: []int32{0}}}}},
		bson.D{{Key: "end_ts", Value: bson.D{
			{Key: "$gte", Value: startTime.Add(-time.Hour * 8).UnixMilli()},
			{Key: "$lte", Value: endTime.Add(-time.Hour * 8).UnixMilli()},
		}}},
	}}}
	assert.Equal(t, expected, got)
}

func TestAdvancedSearchLegacyThreatAliases(t *testing.T) {
	got, err := AdvancedSearch([]AdvancedSearchReq{
		{Name: "threatID", Type: "eq", Value: []string{"flow-0005"}},
		{Name: "threatLevel", Type: "ne", Value: []string{"2"}},
		{Name: "endTm", Type: "lt", Value: []string{"2025-10-19 01:00:00"}},
	})
	require.NoError(t, err)

	endTime, err := parseAdvancedLocalTimeMillis("2025-10-19 01:00:00")
	require.NoError(t, err)
	expected := bson.D{{Key: "$and", Value: bson.A{
		bson.D{{Key: "flow_id", Value: bson.D{{Key: "$in", Value: []string{"flow-0005"}}}}},
		bson.D{{Key: "level", Value: bson.D{{Key: "$nin", Value: []int32{2}}}}},
		bson.D{{Key: "end_ts", Value: bson.D{{Key: "$lte", Value: endTime}}}},
	}}}
	assert.Equal(t, expected, got)
}

func TestAdvancedSearchRejectsInvalidRequests(t *testing.T) {
	_, err := AdvancedSearch([]AdvancedSearchReq{{Name: "unknown", Type: "eq", Value: []string{"x"}}})
	assert.Error(t, err)

	_, err = AdvancedSearch([]AdvancedSearchReq{{Name: "level", Type: "eq", Value: []string{"high"}}})
	assert.Error(t, err)

	_, err = AdvancedSearch([]AdvancedSearchReq{{Name: "time", Type: "bt", Value: []string{"2025-10-19 00:00:00"}}})
	assert.Error(t, err)
}

package scgo

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestWeakPwdFinishIncrement(t *testing.T) {
	tests := []struct {
		name   string
		params any
		want   int32
	}{
		{
			name: "bson array user list",
			params: bson.M{
				"user_list": bson.A{"alice", "bob", "carol"},
			},
			want: 3,
		},
		{
			name: "bson document user list",
			params: bson.D{
				{Key: "user_list", Value: bson.A{"alice", "bob"}},
			},
			want: 2,
		},
		{
			name: "empty list falls back to count",
			params: bson.M{
				"user_list": bson.A{},
				"count":     int32(16),
			},
			want: 16,
		},
		{
			name:   "unknown params keep legacy increment",
			params: "bad",
			want:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := weakPwdFinishIncrement(tt.params); got != tt.want {
				t.Fatalf("weakPwdFinishIncrement() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWeakPwdFinalStatus(t *testing.T) {
	tests := []struct {
		name         string
		finishCount  int64
		failureCount int64
		want         string
	}{
		{name: "finished subtask wins over group warning", finishCount: 1, failureCount: 0, want: "FINISH"},
		{name: "failed subtask fails group", finishCount: 0, failureCount: 1, want: "FAILURE"},
		{name: "no finished subtask fails group", finishCount: 0, failureCount: 0, want: "FAILURE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := weakPwdFinalStatus(tt.finishCount, tt.failureCount); got != tt.want {
				t.Fatalf("weakPwdFinalStatus() = %s, want %s", got, tt.want)
			}
		})
	}
}

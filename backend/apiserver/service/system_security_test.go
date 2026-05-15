package service

import (
	"context"
	"testing"

	apiCommon "ada/backend/apiserver/common"

	"google.golang.org/grpc/metadata"
)

func TestValidNTPAddressRejectsCommandInjection(t *testing.T) {
	valid := []string{
		"pool.ntp.org",
		"cn.pool.ntp.org",
		"10.1.2.3",
	}
	for _, item := range valid {
		if !validNTPAddress(item) {
			t.Fatalf("expected %q to be accepted as an NTP address", item)
		}
	}

	invalid := []string{
		"pool.ntp.org;id",
		"pool.ntp.org && id",
		"$(id).example.com",
		"http://pool.ntp.org",
		"-q",
		"",
	}
	for _, item := range invalid {
		if validNTPAddress(item) {
			t.Fatalf("expected %q to be rejected as an NTP address", item)
		}
	}
}

func TestIsSuperUserContext(t *testing.T) {
	superCtx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("priv", "1"),
	)
	if !isSuperUserContext(superCtx) {
		t.Fatalf("expected priv=%d to be super user", apiCommon.PrivSuper)
	}

	userCtx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("priv", "2"),
	)
	if isSuperUserContext(userCtx) {
		t.Fatalf("expected priv=%d to be non-super user", apiCommon.PrivUser)
	}

	if isSuperUserContext(context.Background()) {
		t.Fatalf("expected context without metadata to be non-super user")
	}
}

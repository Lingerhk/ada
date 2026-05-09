package service

import (
	"context"
	"testing"
	"time"

	"ada/backend/apiserver/config"
	"ada/backend/model"
	dbmongo "ada/infra/mongo"
)

type userActiveMongoStub struct {
	dbmongo.DBAdaptor

	user       *model.User
	userExists bool

	updateByIDCalled bool
	updateRawCalled  bool
	updateID         any
}

func (s *userActiveMongoStub) FindOne(ctx context.Context, name string, query, result any) (error, bool) {
	if !s.userExists {
		return nil, false
	}
	if user, ok := result.(*model.User); ok && s.user != nil {
		*user = *s.user
	}
	return nil, true
}

func (s *userActiveMongoStub) UpdateById(ctx context.Context, name string, id, update any) error {
	s.updateByIDCalled = true
	s.updateID = id
	return nil
}

func (s *userActiveMongoStub) UpdateRaw(ctx context.Context, name string, query, update any, multi bool, upsert ...bool) error {
	s.updateRawCalled = true
	return nil
}

func resetUserActiveTmCache() {
	userActiveTmMutex.Lock()
	userActiveTmCache = make(map[string]time.Time)
	userActiveTmMutex.Unlock()
}

func TestUpdateUserActiveTmRequiresExistingUser(t *testing.T) {
	resetUserActiveTmCache()
	mongoStub := &userActiveMongoStub{}
	svc := (&GrpcService{env: &config.Env{MongoCli: mongoStub}}).withContext(context.Background())

	if err := svc.updateUserActiveTm("admin"); err == nil {
		t.Fatal("expected missing user to return an error")
	}
	if mongoStub.updateByIDCalled {
		t.Fatal("expected missing user not to update active_tm")
	}
	if mongoStub.updateRawCalled {
		t.Fatal("expected updateUserActiveTm not to call UpdateRaw")
	}
}

func TestUpdateUserActiveTmUpdatesExistingUserByID(t *testing.T) {
	resetUserActiveTmCache()
	mongoStub := &userActiveMongoStub{
		userExists: true,
		user:       &model.User{ID: 42, UserName: "adaegis"},
	}
	svc := (&GrpcService{env: &config.Env{MongoCli: mongoStub}}).withContext(context.Background())

	if err := svc.updateUserActiveTm("adaegis"); err != nil {
		t.Fatalf("expected active_tm update to succeed, got %v", err)
	}
	if !mongoStub.updateByIDCalled {
		t.Fatal("expected existing user active_tm to be updated")
	}
	if mongoStub.updateRawCalled {
		t.Fatal("expected updateUserActiveTm not to call UpdateRaw")
	}
	if mongoStub.updateID != int32(42) {
		t.Fatalf("expected update by numeric user id 42, got %v", mongoStub.updateID)
	}
}

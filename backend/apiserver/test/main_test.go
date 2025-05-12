package test

import (
	"context"
	"os"
	"testing"
	"time"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	username = "admin"
	grpcAddr = "192.168.6.4:8800"
)

var ADACli *ADAGrpcClient

type ADAGrpcClient struct {
	cli v2.ADAClient
	ctx context.Context
}

func TestMain(m *testing.M) {
	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := v2.NewADAClient(conn)
	exp := time.Now().AddDate(0, 0, 90).Unix()
	token, err := util.GenerateToken(username, common.RoleMgr, common.PrivSuper, exp)
	if err != nil {
		panic(err)
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	ADACli = &ADAGrpcClient{
		cli: client,
		ctx: ctx,
	}
	os.Exit(m.Run())
}

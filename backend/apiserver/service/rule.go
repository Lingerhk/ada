package service

import (
	"context"

	v2 "ada/backend/apiserver/api/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Alert Rule methods

func (s *ADAServiceV2) ListAlertRule(ctx context.Context, in *v2.ListAlertRuleReq) (*v2.ListAlertRuleReply, error) {
	// TODO: Implement alert rule listing
	return nil, status.Error(codes.Unimplemented, "ListAlertRule not implemented yet")
}

func (s *ADAServiceV2) AddAlertRule(ctx context.Context, in *v2.AddAlertRuleReq) (*v2.AddAlertRuleReply, error) {
	// TODO: Implement alert rule creation
	return nil, status.Error(codes.Unimplemented, "AddAlertRule not implemented yet")
}

func (s *ADAServiceV2) UpdateAlertRule(ctx context.Context, in *v2.UpdateAlertRuleReq) (*v2.UpdateAlertRuleReply, error) {
	// TODO: Implement alert rule update
	return nil, status.Error(codes.Unimplemented, "UpdateAlertRule not implemented yet")
}

func (s *ADAServiceV2) DeleteAlertRule(ctx context.Context, in *v2.DeleteAlertRuleReq) (*v2.DeleteAlertRuleReply, error) {
	// TODO: Implement alert rule deletion
	return nil, status.Error(codes.Unimplemented, "DeleteAlertRule not implemented yet")
}

// Activity Rule methods (Sigma rules)

func (s *ADAServiceV2) AddActivityRule(ctx context.Context, in *v2.AddActivityRuleReq) (*v2.AddActivityRuleReply, error) {
	// TODO: Implement activity rule creation
	// This will store Sigma rules from engine/rules/winlog and engine/rules/pktlog
	return nil, status.Error(codes.Unimplemented, "AddActivityRule not implemented yet")
}

func (s *ADAServiceV2) UpdateActivityRule(ctx context.Context, in *v2.UpdateActivityRuleReq) (*v2.UpdateActivityRuleReply, error) {
	// TODO: Implement activity rule update
	return nil, status.Error(codes.Unimplemented, "UpdateActivityRule not implemented yet")
}

func (s *ADAServiceV2) DeleteActivityRule(ctx context.Context, in *v2.DeleteActivityRuleReq) (*v2.DeleteActivityRuleReply, error) {
	// TODO: Implement activity rule deletion
	return nil, status.Error(codes.Unimplemented, "DeleteActivityRule not implemented yet")
}

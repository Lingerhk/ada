package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/util"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type mcpUserClaimKey struct{}

const defaultMCPPageSize int32 = 20

// NewMCPHTTPHandler returns an authenticated streamable HTTP MCP endpoint.
func NewMCPHTTPHandler(env *config.Env) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "adaegis-apiserver",
		Version: "v1",
	}, nil)

	svc := &ADAServiceV2{
		env:      env,
		language: getSysLanguage(env),
	}
	registerMCPTools(server, svc)

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, err := authenticateMCPRequest(req, env)
		if err != nil {
			logger.Warnf("mcp auth failed: %v", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, req.WithContext(ctx))
	})
}

func authenticateMCPRequest(req *http.Request, env *config.Env) (context.Context, error) {
	token, err := bearerToken(req.Header.Get(_headerAuthz))
	if err != nil {
		return nil, err
	}

	ctx := req.Context()
	gs := (&GrpcService{env: env}).withContext(ctx)
	claim, err := util.ParseToken(token, common.JWT_SECRET)
	if err != nil {
		if !errors.Is(err, util.ErrInvalidJwtToken) {
			return nil, err
		}
		claim, err = gs.authenticateByAccessKey(token)
		if err != nil {
			return nil, err
		}
	} else {
		lastLoginExpireTime, err := gs.getLastLoginExpireTime(ctx, claim.User)
		if err == nil && lastLoginExpireTime > claim.Expired {
			return nil, fmt.Errorf("already logged")
		}
		if err := gs.updateUserActiveTm(claim.User); err != nil {
			return nil, err
		}
	}

	md := metadata.Pairs(
		_headerAuthz, _bearer+" "+token,
		"token", token,
		"user", claim.User,
		"role", claim.Role,
		"priv", strconv.Itoa(claim.Priv),
	)
	if ip := requestRemoteIP(req); ip != "" {
		md.Append("x-real-ip", ip)
	}
	ctx = metadata.NewIncomingContext(ctx, md)
	ctx = context.WithValue(ctx, mcpUserClaimKey{}, claim)
	return ctx, nil
}

func bearerToken(header string) (string, error) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != _bearer || parts[1] == "" {
		return "", fmt.Errorf("missing bearer token")
	}
	return parts[1], nil
}

func requestRemoteIP(req *http.Request) string {
	for _, header := range []string{"X-Real-IP", "X-Forwarded-For"} {
		value := strings.TrimSpace(req.Header.Get(header))
		if value == "" {
			continue
		}
		if header == "X-Forwarded-For" {
			value = strings.TrimSpace(strings.Split(value, ",")[0])
		}
		return value
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func requireMCPAccess(ctx context.Context, fullMethod string) error {
	claim, ok := ctx.Value(mcpUserClaimKey{}).(*util.UserClaim)
	if !ok || claim == nil {
		return status.Error(codes.Unauthenticated, "Unauthenticated")
	}
	ok, err := authentication(claim, fullMethod)
	if err != nil {
		return status.Errorf(codes.Internal, "Authorization failed:%v", err)
	}
	if !ok {
		return status.Error(codes.PermissionDenied, "No permission")
	}
	return nil
}

func callMCP(ctx context.Context, fullMethod string, fn func(context.Context) (proto.Message, error)) (*mcp.CallToolResult, any, error) {
	if err := requireMCPAccess(ctx, fullMethod); err != nil {
		return nil, nil, err
	}
	reply, err := fn(ctx)
	if err != nil {
		return nil, nil, err
	}
	out, err := protoMessageToMap(reply)
	return nil, out, err
}

func protoMessageToMap(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return map[string]any{}, nil
	}
	data, err := protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any)
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizePage(pageIdx, pageSize int32) (int32, int32) {
	if pageIdx <= 0 {
		pageIdx = 1
	}
	if pageSize <= 0 {
		pageSize = defaultMCPPageSize
	}
	return pageIdx, pageSize
}

func registerMCPTools(server *mcp.Server, svc *ADAServiceV2) {
	registerMCPAlertTools(server, svc)
	registerMCPAlertRuleTools(server, svc)
	registerMCPActivityRuleTools(server, svc)
	registerMCPScanRiskTools(server, svc)
}

type mcpListAlertsInput struct {
	PageIdx        int32                 `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize       int32                 `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	IDs            []string              `json:"ids,omitempty" jsonschema:"alert IDs"`
	Level          []int32               `json:"level,omitempty" jsonschema:"risk levels: 5 critical, 4 high, 3 medium, 2 low"`
	EventStatus    int32                 `json:"eventStatus,omitempty" jsonschema:"event status: 0 pending, 1 processed, 2 whitelisted, 3 blocked"`
	StartTm        string                `json:"startTm,omitempty" jsonschema:"start time"`
	EndTm          string                `json:"endTm,omitempty" jsonschema:"end time"`
	SearchType     int32                 `json:"searchType,omitempty" jsonschema:"0 normal search, 1 advanced search"`
	AdvancedSearch []mcpAdvancedSearchIn `json:"advancedSearch,omitempty" jsonschema:"advanced search conditions"`
	SortTm         int32                 `json:"sortTm,omitempty" jsonschema:"time sort: 1 asc, -1 desc"`
}

type mcpAdvancedSearchIn struct {
	Name  string   `json:"name,omitempty"`
	Type  string   `json:"type,omitempty"`
	Value []string `json:"value,omitempty"`
}

type mcpIDInput struct {
	ID string `json:"id" jsonschema:"record ID"`
}

type mcpDisposeAlertInput struct {
	ID          string `json:"id" jsonschema:"alert ID"`
	EventStatus int32  `json:"eventStatus" jsonschema:"event status: 1 processed, 2 whitelisted, 3 blocked"`
	Remark      string `json:"remark,omitempty" jsonschema:"remark"`
}

func registerMCPAlertTools(server *mcp.Server, svc *ADAServiceV2) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "alerts_list",
		Description: "List security alerts with filters and pagination.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListAlertsInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		req := &v2.ListThreatReq{
			PageIdx:     pageIdx,
			PageSize:    pageSize,
			IDs:         in.IDs,
			Level:       in.Level,
			EventStatus: in.EventStatus,
			StartTm:     in.StartTm,
			EndTm:       in.EndTm,
			SearchType:  in.SearchType,
			SortTm:      in.SortTm,
		}
		for _, item := range in.AdvancedSearch {
			req.AdvancedSearch = append(req.AdvancedSearch, &v2.ListThreatReq_Details{
				Name:  item.Name,
				Type:  item.Type,
				Value: item.Value,
			})
		}
		return callMCP(ctx, "/ada.ADA/ListThreat", func(ctx context.Context) (proto.Message, error) {
			return svc.ListThreat(ctx, req)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "alerts_get",
		Description: "Get one security alert detail by ID.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpIDInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/GetThreat", func(ctx context.Context) (proto.Message, error) {
			return svc.GetThreat(ctx, &v2.GetThreatReq{ID: in.ID})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "alerts_dispose",
		Description: "Dispose one security alert by setting its event status and remark.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpDisposeAlertInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/ActionThreat", func(ctx context.Context) (proto.Message, error) {
			return svc.ActionThreat(ctx, &v2.ActionThreatReq{
				ID:          in.ID,
				EventStatus: in.EventStatus,
				Remark:      in.Remark,
			})
		})
	})
}

type mcpListAlertRulesInput struct {
	PageIdx  int32    `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize int32    `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	Level    []int32  `json:"level,omitempty" jsonschema:"rule levels: 5 critical, 4 high, 3 medium, 2 low, 1 info"`
	Status   []string `json:"status,omitempty" jsonschema:"rule status: test, experimental, stable, deprecated"`
	Enable   bool     `json:"enable,omitempty" jsonschema:"filter enabled rules when true"`
	Keyword  string   `json:"keyword,omitempty" jsonschema:"keyword search for title or description"`
	Tags     []string `json:"tags,omitempty" jsonschema:"rule tags"`
	SortTm   int32    `json:"sortTm,omitempty" jsonschema:"time sort: 1 asc, -1 desc"`
}

type mcpAlertDetectionInput struct {
	EventType  string   `json:"eventType,omitempty" jsonschema:"event type: count, multi_eve, multi_pkt, multi_eve_pkt"`
	WinSize    string   `json:"winSize,omitempty" jsonschema:"window size"`
	Sorted     bool     `json:"sorted,omitempty" jsonschema:"whether events are sorted"`
	SigmaRules []string `json:"sigmaRules,omitempty" jsonschema:"related sigma rule IDs"`
	MatchBy    string   `json:"matchBy,omitempty" jsonschema:"match condition"`
}

type mcpAttackFlowInput struct {
	Desc    string              `json:"desc,omitempty" jsonschema:"attack flow description"`
	Fields  []mcpAttackFlowItem `json:"fields,omitempty" jsonschema:"attack flow fields"`
	Relates []string            `json:"relates,omitempty" jsonschema:"related nodes"`
}

type mcpAttackFlowItem struct {
	Obj   string `json:"obj,omitempty" jsonschema:"object type: ip, user, computer, dc"`
	Key   string `json:"key,omitempty" jsonschema:"source field key"`
	Value string `json:"value,omitempty" jsonschema:"resolved value, only used in alert detail output"`
}

type mcpAddAlertRuleInput struct {
	ID           string                  `json:"id,omitempty" jsonschema:"optional custom alert rule ID"`
	Title        string                  `json:"title" jsonschema:"rule title"`
	Description  string                  `json:"description,omitempty" jsonschema:"rule description"`
	Enable       bool                    `json:"enable,omitempty" jsonschema:"whether the rule is enabled"`
	Level        int32                   `json:"level" jsonschema:"rule level, 1-5"`
	Status       string                  `json:"status,omitempty" jsonschema:"rule status"`
	Tags         []string                `json:"tags,omitempty" jsonschema:"rule tags"`
	Logsource    string                  `json:"logsource,omitempty" jsonschema:"log source"`
	Detection    *mcpAlertDetectionInput `json:"detection,omitempty" jsonschema:"alert detection definition"`
	Type         string                  `json:"type,omitempty" jsonschema:"rule category"`
	References   []string                `json:"references,omitempty" jsonschema:"references"`
	Suggestion   string                  `json:"suggestion,omitempty" jsonschema:"remediation suggestion"`
	Author       string                  `json:"author,omitempty" jsonschema:"author"`
	AutoBlock    bool                    `json:"autoBlock,omitempty" jsonschema:"whether to auto block"`
	AttackFlow   *mcpAttackFlowInput     `json:"attackFlow,omitempty" jsonschema:"attack flow"`
	UniqueFilter []string                `json:"uniqueFilter,omitempty" jsonschema:"unique filters"`
}

type mcpUpdateAlertRuleInput struct {
	ID           string                  `json:"id" jsonschema:"alert rule ID"`
	Title        string                  `json:"title,omitempty" jsonschema:"rule title"`
	Description  string                  `json:"description,omitempty" jsonschema:"rule description"`
	Enable       bool                    `json:"enable,omitempty" jsonschema:"whether the rule is enabled"`
	Level        int32                   `json:"level,omitempty" jsonschema:"rule level, 1-5"`
	Status       string                  `json:"status,omitempty" jsonschema:"rule status"`
	Tags         []string                `json:"tags,omitempty" jsonschema:"rule tags"`
	Logsource    string                  `json:"logsource,omitempty" jsonschema:"log source"`
	Detection    *mcpAlertDetectionInput `json:"detection,omitempty" jsonschema:"alert detection definition"`
	Type         string                  `json:"type,omitempty" jsonschema:"rule category"`
	References   []string                `json:"references,omitempty" jsonschema:"references"`
	Suggestion   string                  `json:"suggestion,omitempty" jsonschema:"remediation suggestion"`
	Author       string                  `json:"author,omitempty" jsonschema:"author"`
	AutoBlock    bool                    `json:"autoBlock,omitempty" jsonschema:"whether to auto block"`
	AttackFlow   *mcpAttackFlowInput     `json:"attackFlow,omitempty" jsonschema:"attack flow"`
	UniqueFilter []string                `json:"uniqueFilter,omitempty" jsonschema:"unique filters"`
}

func toAlertDetection(in *mcpAlertDetectionInput) *v2.AlertDetection {
	if in == nil {
		return nil
	}
	return &v2.AlertDetection{
		EventType:  in.EventType,
		WinSize:    in.WinSize,
		Sorted:     in.Sorted,
		SigmaRules: in.SigmaRules,
		MatchBy:    in.MatchBy,
	}
}

func toAttackFlow(in *mcpAttackFlowInput) *v2.AttackFlowReply {
	if in == nil {
		return nil
	}
	out := &v2.AttackFlowReply{
		Desc:    in.Desc,
		Relates: in.Relates,
	}
	for _, field := range in.Fields {
		out.Fields = append(out.Fields, &v2.AttackFlowReply_Field{
			Obj:   field.Obj,
			Key:   field.Key,
			Value: field.Value,
		})
	}
	return out
}

func registerMCPAlertRuleTools(server *mcp.Server, svc *ADAServiceV2) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "alert_rules_list",
		Description: "List alert correlation rules.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListAlertRulesInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		return callMCP(ctx, "/ada.ADA/ListAlertRule", func(ctx context.Context) (proto.Message, error) {
			return svc.ListAlertRule(ctx, &v2.ListAlertRuleReq{
				PageIdx:  pageIdx,
				PageSize: pageSize,
				Level:    in.Level,
				Status:   in.Status,
				Enable:   in.Enable,
				Keyword:  in.Keyword,
				Tags:     in.Tags,
				SortTm:   in.SortTm,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "alert_rules_add",
		Description: "Create an alert correlation rule.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAddAlertRuleInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/AddAlertRule", func(ctx context.Context) (proto.Message, error) {
			return svc.AddAlertRule(ctx, &v2.AddAlertRuleReq{
				ID:           in.ID,
				Title:        in.Title,
				Description:  in.Description,
				Enable:       in.Enable,
				Level:        in.Level,
				Status:       in.Status,
				Tags:         in.Tags,
				Logsource:    in.Logsource,
				Detection:    toAlertDetection(in.Detection),
				Type:         in.Type,
				References:   in.References,
				Suggestion:   in.Suggestion,
				Author:       in.Author,
				AutoBlock:    in.AutoBlock,
				AttackFlow:   toAttackFlow(in.AttackFlow),
				UniqueFilter: in.UniqueFilter,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "alert_rules_update",
		Description: "Update an alert correlation rule.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpUpdateAlertRuleInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/UpdateAlertRule", func(ctx context.Context) (proto.Message, error) {
			return svc.UpdateAlertRule(ctx, &v2.UpdateAlertRuleReq{
				ID:           in.ID,
				Title:        in.Title,
				Description:  in.Description,
				Enable:       in.Enable,
				Level:        in.Level,
				Status:       in.Status,
				Tags:         in.Tags,
				Logsource:    in.Logsource,
				Detection:    toAlertDetection(in.Detection),
				Type:         in.Type,
				References:   in.References,
				Suggestion:   in.Suggestion,
				Author:       in.Author,
				AutoBlock:    in.AutoBlock,
				AttackFlow:   toAttackFlow(in.AttackFlow),
				UniqueFilter: in.UniqueFilter,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "alert_rules_delete",
		Description: "Delete an alert correlation rule.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpIDInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/DeleteAlertRule", func(ctx context.Context) (proto.Message, error) {
			return svc.DeleteAlertRule(ctx, &v2.DeleteAlertRuleReq{ID: in.ID})
		})
	})
}

type mcpListActivityRulesInput struct {
	PageIdx   int32    `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize  int32    `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	IDs       []string `json:"ids,omitempty" jsonschema:"activity rule IDs"`
	Level     []int32  `json:"level,omitempty" jsonschema:"rule levels: 5 critical, 4 high, 3 medium, 2 low, 1 info"`
	Status    []string `json:"status,omitempty" jsonschema:"rule status"`
	Keyword   string   `json:"keyword,omitempty" jsonschema:"keyword search"`
	Tags      []string `json:"tags,omitempty" jsonschema:"rule tags"`
	Logsource string   `json:"logsource,omitempty" jsonschema:"log source"`
	RuleType  string   `json:"ruleType,omitempty" jsonschema:"rule type: winlog, pktlog, flow"`
	SortTm    int32    `json:"sortTm,omitempty" jsonschema:"time sort: 1 asc, -1 desc"`
}

type mcpAddActivityRuleInput struct {
	ID           string   `json:"id" jsonschema:"activity rule ID"`
	Title        string   `json:"title" jsonschema:"rule title"`
	Description  string   `json:"description,omitempty" jsonschema:"rule description"`
	Level        int32    `json:"level" jsonschema:"rule level, 1-5"`
	Status       string   `json:"status,omitempty" jsonschema:"rule status"`
	Tags         []string `json:"tags,omitempty" jsonschema:"rule tags"`
	Logsource    string   `json:"logsource,omitempty" jsonschema:"log source"`
	References   []string `json:"references,omitempty" jsonschema:"references"`
	Detection    string   `json:"detection" jsonschema:"activity detection YAML"`
	RdxKey       string   `json:"rdxKey,omitempty" jsonschema:"redis cache key"`
	Fields       []string `json:"fields,omitempty" jsonschema:"extracted fields"`
	UniqueFields []string `json:"uniqueFields,omitempty" jsonschema:"unique fields"`
	Author       string   `json:"author,omitempty" jsonschema:"author"`
}

type mcpUpdateActivityRuleInput struct {
	ID           string   `json:"id" jsonschema:"activity rule ID"`
	Title        string   `json:"title,omitempty" jsonschema:"rule title"`
	Description  string   `json:"description,omitempty" jsonschema:"rule description"`
	Level        int32    `json:"level,omitempty" jsonschema:"rule level, 1-5"`
	Status       string   `json:"status,omitempty" jsonschema:"rule status"`
	Tags         []string `json:"tags,omitempty" jsonschema:"rule tags"`
	Logsource    string   `json:"logsource,omitempty" jsonschema:"log source"`
	References   []string `json:"references,omitempty" jsonschema:"references"`
	Detection    string   `json:"detection,omitempty" jsonschema:"activity detection YAML"`
	RdxKey       string   `json:"rdxKey,omitempty" jsonschema:"redis cache key"`
	Fields       []string `json:"fields,omitempty" jsonschema:"extracted fields"`
	UniqueFields []string `json:"uniqueFields,omitempty" jsonschema:"unique fields"`
	Author       string   `json:"author,omitempty" jsonschema:"author"`
}

func registerMCPActivityRuleTools(server *mcp.Server, svc *ADAServiceV2) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "activity_rules_list",
		Description: "List Sigma/activity rules.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListActivityRulesInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		return callMCP(ctx, "/ada.ADA/ListActivityRule", func(ctx context.Context) (proto.Message, error) {
			return svc.ListActivityRule(ctx, &v2.ListActivityRuleReq{
				PageIdx:   pageIdx,
				PageSize:  pageSize,
				IDs:       in.IDs,
				Level:     in.Level,
				Status:    in.Status,
				Keyword:   in.Keyword,
				Tags:      in.Tags,
				Logsource: in.Logsource,
				RuleType:  in.RuleType,
				SortTm:    in.SortTm,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "activity_rules_add",
		Description: "Create a Sigma/activity rule.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAddActivityRuleInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/AddActivityRule", func(ctx context.Context) (proto.Message, error) {
			return svc.AddActivityRule(ctx, &v2.AddActivityRuleReq{
				ID:           in.ID,
				Title:        in.Title,
				Description:  in.Description,
				Level:        in.Level,
				Status:       in.Status,
				Tags:         in.Tags,
				Logsource:    in.Logsource,
				References:   in.References,
				Detection:    in.Detection,
				RdxKey:       in.RdxKey,
				Fields:       in.Fields,
				UniqueFields: in.UniqueFields,
				Author:       in.Author,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "activity_rules_update",
		Description: "Update a Sigma/activity rule.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpUpdateActivityRuleInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/UpdateActivityRule", func(ctx context.Context) (proto.Message, error) {
			return svc.UpdateActivityRule(ctx, &v2.UpdateActivityRuleReq{
				ID:           in.ID,
				Title:        in.Title,
				Description:  in.Description,
				Level:        in.Level,
				Status:       in.Status,
				Tags:         in.Tags,
				Logsource:    in.Logsource,
				References:   in.References,
				Detection:    in.Detection,
				RdxKey:       in.RdxKey,
				Fields:       in.Fields,
				UniqueFields: in.UniqueFields,
				Author:       in.Author,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "activity_rules_delete",
		Description: "Delete a Sigma/activity rule.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpIDInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/DeleteActivityRule", func(ctx context.Context) (proto.Message, error) {
			return svc.DeleteActivityRule(ctx, &v2.DeleteActivityRuleReq{ID: in.ID})
		})
	})
}

type mcpListBaselineInput struct {
	PageIdx       int32    `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize      int32    `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	Domain        []string `json:"domain,omitempty" jsonschema:"domains"`
	SubType       []string `json:"subType,omitempty" jsonschema:"baseline sub types"`
	Level         []int32  `json:"level,omitempty" jsonschema:"risk levels"`
	Result        []int32  `json:"result,omitempty" jsonschema:"scan result status"`
	Search        string   `json:"search,omitempty" jsonschema:"search keyword"`
	OrderUpdateTm int32    `json:"orderUpdateTm,omitempty" jsonschema:"update time sort: 1 asc, -1 desc"`
}

type mcpListLeakInput struct {
	PageIdx       int32    `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize      int32    `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	Domain        []string `json:"domain,omitempty" jsonschema:"domains"`
	SubType       []string `json:"subType,omitempty" jsonschema:"vulnerability sub types"`
	Level         []int32  `json:"level,omitempty" jsonschema:"risk levels"`
	Result        []int32  `json:"result,omitempty" jsonschema:"scan result status"`
	Search        string   `json:"search,omitempty" jsonschema:"search keyword"`
	StartTm       string   `json:"startTm,omitempty" jsonschema:"start time"`
	EndTm         string   `json:"endTm,omitempty" jsonschema:"end time"`
	OrderUpdateTm int32    `json:"orderUpdateTm,omitempty" jsonschema:"update time sort: 1 asc, -1 desc"`
}

type mcpListWeakPwdInput struct {
	PageIdx       int32    `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize      int32    `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	Domain        []string `json:"domain,omitempty" jsonschema:"domains"`
	Locked        []int32  `json:"locked,omitempty" jsonschema:"lock status: 1 locked, 0 normal"`
	IsPlain       bool     `json:"isPlain,omitempty" jsonschema:"whether to return plaintext weak passwords"`
	Search        string   `json:"search,omitempty" jsonschema:"search keyword"`
	OrderUpdateTm int32    `json:"orderUpdateTm,omitempty" jsonschema:"update time sort: 1 asc, -1 desc"`
}

type mcpListScanTaskInput struct {
	PageIdx       int32  `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize      int32  `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
	Cycle         string `json:"cycle,omitempty" jsonschema:"all, cycle, once"`
	Type          string `json:"type,omitempty" jsonschema:"all, baseline, leak, weakpwd"`
	Status        string `json:"status,omitempty" jsonschema:"all, PENDING, RUNNING, FINISH, FAILURE"`
	StartTm       string `json:"startTm,omitempty" jsonschema:"start time"`
	EndTm         string `json:"endTm,omitempty" jsonschema:"end time"`
	OrderCreateTm int32  `json:"orderCreateTm,omitempty" jsonschema:"create time sort: 1 asc, -1 desc"`
	OrderUpdateTm int32  `json:"orderUpdateTm,omitempty" jsonschema:"update time sort: 1 asc, -1 desc"`
}

type mcpGetScanTaskInput struct {
	ID       string `json:"id" jsonschema:"scan task ID"`
	PageIdx  int32  `json:"pageIdx,omitempty" jsonschema:"page index, starting from 1"`
	PageSize int32  `json:"pageSize,omitempty" jsonschema:"page size, default 20"`
}

type mcpAddScanTaskInput struct {
	Type  string            `json:"type" jsonschema:"baseline, leak, or weakpwd"`
	Plans map[string]string `json:"plans" jsonschema:"domain to scan template ID map"`
}

type mcpRecheckScanTaskInput struct {
	ID   string `json:"id" jsonschema:"subtask ID"`
	Type string `json:"type" jsonschema:"baseline, leak, or weakpwd"`
}

func registerMCPScanRiskTools(server *mcp.Server, svc *ADAServiceV2) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_baselines_list",
		Description: "List baseline scan risk results.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListBaselineInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		return callMCP(ctx, "/ada.ADA/ListBaseline", func(ctx context.Context) (proto.Message, error) {
			return svc.ListBaseline(ctx, &v2.ListBaselineReq{
				PageIdx:       pageIdx,
				PageSize:      pageSize,
				Domain:        in.Domain,
				SubType:       in.SubType,
				Level:         in.Level,
				Result:        in.Result,
				Search:        in.Search,
				OrderUpdateTm: in.OrderUpdateTm,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_baselines_get",
		Description: "Get one baseline scan risk result detail.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpIDInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/GetBaseline", func(ctx context.Context) (proto.Message, error) {
			return svc.GetBaseline(ctx, &v2.GetBaselineReq{ID: in.ID})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_vulnerabilities_list",
		Description: "List vulnerability scan risk results.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListLeakInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		return callMCP(ctx, "/ada.ADA/ListLeak", func(ctx context.Context) (proto.Message, error) {
			return svc.ListLeak(ctx, &v2.ListLeakReq{
				PageIdx:       pageIdx,
				PageSize:      pageSize,
				Domain:        in.Domain,
				SubType:       in.SubType,
				Level:         in.Level,
				Result:        in.Result,
				Search:        in.Search,
				StartTm:       in.StartTm,
				EndTm:         in.EndTm,
				OrderUpdateTm: in.OrderUpdateTm,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_weak_passwords_list",
		Description: "List weak password scan risk results.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListWeakPwdInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		return callMCP(ctx, "/ada.ADA/ListWeakPwd", func(ctx context.Context) (proto.Message, error) {
			return svc.ListWeakPwd(ctx, &v2.ListWeakPwdReq{
				PageIdx:       pageIdx,
				PageSize:      pageSize,
				Domain:        in.Domain,
				Locked:        in.Locked,
				IsPlain:       in.IsPlain,
				Search:        in.Search,
				OrderUpdateTm: in.OrderUpdateTm,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_tasks_list",
		Description: "List baseline, vulnerability, and weak password scan tasks.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpListScanTaskInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		if in.Cycle == "" {
			in.Cycle = "all"
		}
		if in.Type == "" {
			in.Type = "all"
		}
		if in.Status == "" {
			in.Status = "all"
		}
		return callMCP(ctx, "/ada.ADA/ListScanTask", func(ctx context.Context) (proto.Message, error) {
			return svc.ListScanTask(ctx, &v2.ListScanTaskReq{
				PageIdx:       pageIdx,
				PageSize:      pageSize,
				Cycle:         in.Cycle,
				Type:          in.Type,
				Status:        in.Status,
				StartTm:       in.StartTm,
				EndTm:         in.EndTm,
				OrderCreateTm: in.OrderCreateTm,
				OrderUpdateTm: in.OrderUpdateTm,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_tasks_get",
		Description: "Get one scan task detail and its subtask result rows.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpGetScanTaskInput) (*mcp.CallToolResult, any, error) {
		pageIdx, pageSize := normalizePage(in.PageIdx, in.PageSize)
		return callMCP(ctx, "/ada.ADA/GetScanTask", func(ctx context.Context) (proto.Message, error) {
			return svc.GetScanTask(ctx, &v2.GetScanTaskReq{
				ID:       in.ID,
				PageIdx:  pageIdx,
				PageSize: pageSize,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_tasks_run",
		Description: "Start a baseline, vulnerability, or weak password scan task.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAddScanTaskInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/AddScanTask", func(ctx context.Context) (proto.Message, error) {
			return svc.AddScanTask(ctx, &v2.AddScanTaskReq{
				Type:  in.Type,
				Plans: in.Plans,
			})
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_tasks_recheck",
		Description: "Run a recheck for one baseline, vulnerability, or weak password subtask.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpRecheckScanTaskInput) (*mcp.CallToolResult, any, error) {
		return callMCP(ctx, "/ada.ADA/RecheckScanTask", func(ctx context.Context) (proto.Message, error) {
			return svc.RecheckScanTask(ctx, &v2.RecheckScanTaskReq{
				ID:   in.ID,
				Type: in.Type,
			})
		})
	})
}

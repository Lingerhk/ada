package v2

import (
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// TestAllMessageRulesCompile makes sure that every (buf.validate.field) rule in
// ada.proto compiles: protovalidate compiles rules lazily, so a broken regular
// expression would otherwise only surface as an InvalidArgument at runtime.
func TestAllMessageRulesCompile(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}

	var walk func(msgs protoreflect.MessageDescriptors)
	walk = func(msgs protoreflect.MessageDescriptors) {
		for i := 0; i < msgs.Len(); i++ {
			md := msgs.Get(i)
			err := v.Validate(dynamicpb.NewMessage(md))
			var cerr *protovalidate.CompilationError
			if err != nil {
				if ok := asCompilationError(err, &cerr); ok {
					t.Errorf("%s: rule compilation failed: %v", md.FullName(), cerr)
				}
			}
			walk(md.Messages())
		}
	}
	walk(File_ada_proto.Messages())
}

func asCompilationError(err error, target **protovalidate.CompilationError) bool {
	if ce, ok := err.(*protovalidate.CompilationError); ok {
		*target = ce
		return true
	}
	return false
}

func TestLoginReqRules(t *testing.T) {
	v, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		req  *LoginReq
		ok   bool
	}{
		{"valid without totp", &LoginReq{Username: "admin", Password: "secret"}, true},
		{"valid with totp", &LoginReq{Username: "admin", Password: "secret", TotpCode: "123456"}, true},
		{"empty username", &LoginReq{Password: "secret"}, false},
		{"empty password", &LoginReq{Username: "admin"}, false},
		{"totp not six digits", &LoginReq{Username: "admin", Password: "secret", TotpCode: "12ab"}, false},
	}
	for _, c := range cases {
		err := v.Validate(c.req)
		if (err == nil) != c.ok {
			t.Errorf("%s: got err=%v, want ok=%v", c.name, err, c.ok)
		}
	}

	if err := v.Validate(&ListUserReq{PageIdx: 0}); err == nil {
		t.Error("pageIdx 0 should be rejected")
	}
	if err := v.Validate(&UpdateUserReq{Mobile: "abc"}); err == nil {
		t.Error("invalid mobile should be rejected")
	}
	if err := v.Validate(&UpdateUserReq{Mobile: ""}); err != nil {
		t.Errorf("empty mobile should be accepted: %v", err)
	}
}

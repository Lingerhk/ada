package test

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"

	logger "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAddUser(t *testing.T) {
	req := v2.AddUserReq{
		Username: "ada",
		Password: "admin@123",
		Role:     common.RoleSec,
	}

	resp, err := ADACli.cli.AddUser(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	Convey("Test API Logout", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}

func TestUpdateUser(t *testing.T) {
	req := v2.UpdateUserReq{
		Username: "admin",
		Role:     common.RoleMgr,
		Mobile:   "1580120091134",
		Email:    "sunfox0903@163.com",
		Remark:   "are you ok?",
	}

	resp, err := ADACli.cli.UpdateUser(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	Convey("Test API Logout", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}
func TestUpdateUserPassword(t *testing.T) {
	req := v2.UpdateUserPasswordReq{
		Username:    "ada",
		OldPassword: "admin@123",
		NewPassword: "ada@2024",
	}

	resp, err := ADACli.cli.UpdateUserPassword(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	Convey("Test API Logout", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}
func TestLogin(t *testing.T) {
	req := v2.LoginReq{
		Username: "ada",
		Password: "ada@2024",
		TotpCode: "",
	}

	resp, err := ADACli.cli.Login(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	Convey("Test API Login", t, func() {
		Convey("Test response status", func() {
			So(resp.Username, ShouldEqual, "admin")
		})
	})
	logger.Infof("%v", resp)
}
func TestLogout(t *testing.T) {
	req := v2.LogoutReq{
		Username: "ada.admin",
	}
	resp, err := ADACli.cli.Logout(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	Convey("Test API Logout", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}
func TestListUser(t *testing.T) {
	req := v2.ListUserReq{
		PageIdx:  1,
		PageSize: 10,
		Search:   "",
		IsSelf:   true,
	}

	resp, err := ADACli.cli.ListUser(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	logger.Infof("%+v", resp)
}

func TestDeleteUser(t *testing.T) {
	req := v2.DeleteUserReq{
		Username: "sunfox",
	}

	resp, err := ADACli.cli.DeleteUser(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	Convey("Test API DeleteUser", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}

func TestCheckMfa(t *testing.T) {
	req := v2.CheckMfaReq{
		Username: "admin",
		Password: "ada@2024",
	}

	resp, err := ADACli.cli.CheckMfa(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	Convey("Test API Login", t, func() {
		Convey("Test response status", func() {
			So(resp.HasMfa, ShouldEqual, "sunfox")
		})
	})
	logger.Infof("%v", resp)
}
func TestEnableMfa(t *testing.T) {
	req := v2.EnableMfaReq{
		Username: "admin",
		Password: "ada@2024",
		Secret:   "QBYIPHG6W9KVAQPGLB21VLSGKZYQMFCB",
		MfaCode:  "049230",
	}

	resp, err := ADACli.cli.EnableMfa(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	Convey("Test API Login", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "sunfox")
		})
	})
	logger.Infof("%v", resp)
}
func TestDisableMfa(t *testing.T) {
	req := v2.DisableMfaReq{
		Username: "linruyi",
	}

	resp, err := ADACli.cli.DisableMfa(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	Convey("Test API Login", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "sunfox")
		})
	})
	logger.Infof("%v", resp)
}

func TestUpdateAvatar(t *testing.T) {
	file, err := os.Open("D:\\code\\test\\file\\Lark20210112-145314.jpeg")
	if err != nil {
		fmt.Println(err)
		return
	}
	fileAll, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}
	toString := base64.StdEncoding.EncodeToString(fileAll)

	req := &v2.UpdateAvatarReq{
		UserId: 54,
		File:   toString,
	}

	avatar, err := ADACli.cli.UpdateAvatar(ADACli.ctx, req)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(avatar)

	bytes, err := base64.StdEncoding.DecodeString(toString)
	if err != nil {
		fmt.Print(err)
		return
	}

	newFile, err := os.Create("D:\\code\\test\\file\\1.png")
	if err != nil {
		fmt.Print(err)
		return
	}
	defer newFile.Close()

	_, err = newFile.Write(bytes)
	if err != nil {
		fmt.Print(err)
		return
	}
}

func TestResetPassword(t *testing.T) {
	req := v2.ResetPasswordReq{
		Username:    "ada.sre",
		NewPassword: "ada@123456",
	}

	reply, err := ADACli.cli.ResetPassword(ADACli.ctx, &req)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(reply)
}

func TestEncryptPassword(t *testing.T) {
	password := "ada@2024"
	plainPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("encrypt password err:%s", err)
	}
	encPswd := string(plainPwd)
	fmt.Println(encPswd)

	hashedPswd := "$2a$04$lzFZP5sZFmNt/pxHJpL.pe88u2LoQ1j2kiJ2ma17/5KuHDinmsMPi"
	err = bcrypt.CompareHashAndPassword([]byte(hashedPswd), []byte(password))
	if err != nil {
		fmt.Printf("compare password err:%s", err)
	}
}

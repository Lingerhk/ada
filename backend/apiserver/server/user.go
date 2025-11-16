package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	"ada/infra/base"
	"ada/infra/crypto"
	utime "ada/infra/time"
	"fmt"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func FindAllUser(e *config.Env, limit, offset int32, search, username string, filterRole, filterMfaStatus, filterPassStrength []string, filterStartCreateTm, filterEndCreateTm, filterStartPassTm, filterEndPassTm string, sort int32) ([]model.User, int64, error) {
	var users []model.User
	tb := (&model.User{}).CollectName()

	// 如果是管理员查询子用户列表则查询所有admin用户
	query := bson.D{}
	if len(username) > 0 {
		query = append(query, bson.E{Key: "username", Value: username})
	}

	if len(filterRole) > 0 {
		query = append(query, bson.E{Key: "role", Value: bson.M{"$in": filterRole}})
	}

	if len(filterMfaStatus) > 0 {
		if base.InArray("stop", filterMfaStatus) || base.InArray("disable", filterMfaStatus) {
			filterMfaStatus = append(filterMfaStatus, "stop")
			filterMfaStatus = append(filterMfaStatus, "disable")
		}
		query = append(query, bson.E{Key: "mfa_status", Value: bson.M{"$in": filterMfaStatus}})
	}

	if len(filterPassStrength) > 0 {
		query = append(query, bson.E{Key: "pass_strength", Value: bson.M{"$in": filterPassStrength}})
	}

	if len(filterStartCreateTm) > 0 && len(filterEndCreateTm) > 0 {
		startTime, err := time.Parse("2006-01-02 15:04:05", filterStartCreateTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, 0, err
		}
		endTime, err := time.Parse("2006-01-02 15:04:05", filterEndCreateTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, 0, err
		}

		//起止日期相同的话截止日期+1，前端没有传时分秒
		if startTime == endTime {
			endTime = endTime.AddDate(0, 0, 1)
		}

		query = append(query, bson.E{Key: "create_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8).Add(time.Second)}})
	}

	if len(filterStartPassTm) > 0 && len(filterEndPassTm) > 0 {
		startTime, err := time.Parse("2006-01-02 15:04:05", filterStartPassTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, 0, err
		}
		endTime, err := time.Parse("2006-01-02 15:04:05", filterEndPassTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, 0, err
		}

		//起止日期相同的话截止日期+1，前端没有传时分秒
		if startTime == endTime {
			endTime = endTime.AddDate(0, 0, 1)
		}

		query = append(query, bson.E{Key: "pwd_update_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8).Add(time.Second)}})
	}

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	var rsort bson.M
	switch sort {
	case 1, -1:
		rsort = bson.M{"create_tm": sort}
	case 2, -2:
		if sort == 2 {
			rsort = bson.M{"pwd_update_tm": 1}
		} else {
			rsort = bson.M{"pwd_update_tm": -1}
		}
	default:
		rsort = bson.M{"create_tm": -1}
	}

	err = e.MongoCli.FindSortByLimitAndSkip(tb, query, rsort, &users, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func GetUser(e *config.Env, userName string) (*model.User, error) {
	var u model.User
	err, exist := e.MongoCli.FindOne(u.CollectName(), bson.M{"username": userName}, &u)
	if err != nil || !exist {
		return nil, err
	}

	return &u, nil
}

func AddUser(e *config.Env, userName, passHash, passStrength, role, mobile, email, remark, department string, priv int32) error {
	var u model.User

	uid, err := e.MongoCli.GetNextSequence(u.CollectName())
	if err != nil {
		return err
	}

	u.ID = uid
	u.UserName = userName
	u.Password = passHash
	u.PassStrength = passStrength
	u.Role = role
	u.Priv = priv
	u.Mobile = mobile
	u.Email = email
	u.Remark = remark
	u.CreateTm = utime.CurTime()
	u.MfaStatus = "disable"
	u.PwdUpdateTm = utime.CurTime()
	u.Department = department
	u.ActiveTm = utime.CurTime()
	u.UpdateTm = utime.CurTime()

	err = e.MongoCli.Insert(u.CollectName(), &u)
	if err != nil {
		return err
	}

	return nil
}

func UpdateUser(e *config.Env, user *model.User) error {
	var u model.User
	// update user property

	query := bson.M{"username": user.UserName}
	err := e.MongoCli.Update(u.CollectName(), &query, &user, false)
	if err != nil {
		return err
	}
	return nil
}

func UpdateUserInfo(e *config.Env, userName, role, password, mobile, email, remark string) error {
	var u model.User

	query := bson.M{"username": userName}

	var updateM bson.M
	if password == "" {
		updateM = bson.M{"$set": bson.M{"mobile": mobile, "email": email, "remark": remark}}
	} else {
		updateM = bson.M{"$set": bson.M{
			"mobile": mobile, "email": email, "remark": remark,
			"password": password, "pwd_update_tm": utime.CurTime(),
		}}
	}

	err := e.MongoCli.UpdateRaw(u.CollectName(), &query, &updateM, false)
	if err != nil {
		return err
	}
	return nil
}

func UpdateUserPassword(e *config.Env, userName, passHash, passStrength string) error {
	var u model.User
	// update user property
	user := bson.M{
		"password":      passHash,
		"pass_strength": passStrength,
		"pwd_update_tm": utime.CurTime(),
	}
	query := bson.M{"username": userName}
	err := e.MongoCli.Update(u.CollectName(), &query, &user, false)
	if err != nil {
		return err
	}
	return nil
}

func UpdateUserSecret(e *config.Env, user *model.User) error {
	query := bson.M{"_id": user.ID}
	update := bson.M{"$set": bson.M{"secret": user.Secret, "mfa_status": "enable"}}
	err := e.MongoCli.UpdateRaw(user.CollectName(), query, update, false)
	if err != nil {
		return err
	}
	return nil
}

func DisableMfa(e *config.Env, user *model.User) error {
	query := bson.M{"_id": user.ID}
	update := bson.M{"$set": bson.M{"secret": "", "mfa_status": "disable"}}
	err := e.MongoCli.UpdateRaw(user.CollectName(), query, update, false)
	if err != nil {
		return err
	}
	return nil
}

func DeleteUser(e *config.Env, userName string) error {
	var u model.User
	query := bson.M{"username": userName}
	err := e.MongoCli.Remove(u.CollectName(), &query, false)
	if err != nil {
		return err
	}
	return nil
}

func UpdateUserAvatar(e *config.Env, userId int32, file string) error {
	user := model.User{}

	update := bson.M{
		"avatar": file,
	}

	err := e.MongoCli.UpdateById(user.CollectName(), userId, &update)
	if err != nil {
		return err
	}
	return nil
}

func FindUserByName(e *config.Env, username string) (*model.User, error) {
	var user model.User
	tb := (&model.User{}).CollectName()

	m := bson.M{"username": username}
	err, _ := e.MongoCli.FindOne(tb, m, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AccessKey functions
func ListAccessKey(e *config.Env, username string) ([]model.AccessKey, error) {
	var keys []model.AccessKey
	tb := (&model.AccessKey{}).CollectName()

	query := bson.M{}
	if username != "" {
		query["username"] = username
	}

	err := e.MongoCli.FindAll(tb, query, &keys)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func GenerateAccessKey(e *config.Env, username, remark string) (string, error) {
	tb := (&model.AccessKey{}).CollectName()

	// Generate SK
	secretKey := fmt.Sprintf("sk-%s", crypto.RandString(25))

	// Create masked display version
	displaySK := fmt.Sprintf("sk-%s*****%s", secretKey[3:6], secretKey[25:])

	// secretKey hash
	hashedSK := crypto.MD5String(secretKey, 32)

	key := model.AccessKey{
		Username:   username,
		SecretKey:  displaySK,
		SecretHash: hashedSK,
		Remark:     remark,
		Status:     "active",
		ActiveTm:   time.Now(),
		CreateTm:   time.Now(),
		UpdateTm:   time.Now(),
	}

	err := e.MongoCli.Insert(tb, key)
	if err != nil {
		logger.Errorf("insert access key error: %v", err)
		return "", err
	}

	// Return plain text secretKey (only returned once)
	return secretKey, nil
}

func GetAccessKey(e *config.Env, id string) (*model.AccessKey, error) {
	var key model.AccessKey
	tb := (&model.AccessKey{}).CollectName()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	m := bson.M{"_id": objID}
	err, _ = e.MongoCli.FindOne(tb, m, &key)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

func DeleteAccessKey(e *config.Env, id string) error {
	tb := (&model.AccessKey{}).CollectName()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	m := bson.M{"_id": objID}
	update := bson.M{
		"$set": bson.M{
			"status":    "disabled",
			"update_tm": time.Now(),
		},
	}
	err = e.MongoCli.UpdateRaw(tb, m, update, false)
	if err != nil {
		logger.Errorf("disable access key error: %v", err)
		return err
	}

	return nil
}

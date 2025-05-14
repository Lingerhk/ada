package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	utime "ada/infra/time"
	"fmt"
	"net/url"
	"strings"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func GetDomainList(env *config.Env) ([]*model.Domain, error) {
	domain := model.Domain{}
	domainList := make([]*model.Domain, 0)

	if err := env.MongoCli.FindAll(domain.CollectName(), bson.M{}, &domainList); err != nil {
		return nil, err
	}

	return domainList, nil
}

func FindAllDomain(e *config.Env, limit, skip int64, FilterDomain string, FilterStatus string, KeyWord string) ([]model.Domain, int64, error) {
	var domainList []model.Domain
	tb := (&model.Domain{}).CollectName()

	query := bson.D{}

	if len(FilterDomain) > 0 {
		Fn := strings.Split(FilterDomain, ",")
		query = append(query, bson.E{Key: "name", Value: bson.M{"$in": Fn}})

	}

	if len(FilterStatus) > 0 {
		Fn := strings.Split(FilterStatus, ",")
		query = append(query, bson.E{Key: "status", Value: bson.M{"$in": Fn}})
	}

	if len(KeyWord) > 0 {
		var b []bson.M

		b = append(b, bson.M{
			"dc_hostname": bson.M{"$regex": escaping(KeyWord), "$options": "i"},
		})
		b = append(b, bson.M{
			"ldap_conf.user": bson.M{"$regex": escaping(KeyWord), "$options": "i"},
		})

		query = append(query, bson.E{Key: "$or", Value: b})
	}

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}
	if err := e.MongoCli.FindByLimitAndSkip(tb, query, &domainList, limit, skip); err != nil {
		return nil, 0, err
	}
	return domainList, total, nil
}

func FindAllDomainByStatus(e *config.Env, status string) ([]model.Domain, error) {
	var domainList []model.Domain
	tb := (&model.Domain{}).CollectName()

	query := bson.M{"status": status}

	err := e.MongoCli.FindAll(tb, query, &domainList)
	if err != nil {
		return nil, err
	}
	return domainList, nil
}

func GetDomainByName(e *config.Env, domain string) (*model.Domain, error) {
	var dm model.Domain
	err, exist := e.MongoCli.FindOne(dm.CollectName(), bson.M{"name": domain}, &dm)
	if err != nil || !exist {
		return nil, err
	}

	return &dm, nil
}

func GetDomainById(e *config.Env, id string) (*model.Domain, error) {
	var dm model.Domain
	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	err, exist := e.MongoCli.FindOne(dm.CollectName(), bson.M{"_id": Id}, &dm)
	if err != nil || !exist {
		return nil, err
	}

	return &dm, nil
}

func AddDomain(e *config.Env, name, dcHostName, status string, ldapConf map[string]string) error {
	var domain model.Domain
	domain.Name = name
	domain.DCHostName = dcHostName
	domain.Status = status
	domain.LdapConf = ldapConf
	domain.CreateTm = utime.CurTime()
	err := e.MongoCli.Insert(domain.CollectName(), &domain)
	if err != nil {
		return err
	}

	return nil
}

func UpdateDomain(e *config.Env, id, name, dcHostName, status string, ldapConf map[string]string, DCList []model.DCList) error {
	var domain model.Domain
	domain.Name = name
	domain.DCHostName = dcHostName
	domain.Status = status
	domain.LdapConf = ldapConf
	domain.DCList = DCList
	domain.CreateTm = utime.CurTime()
	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	err = e.MongoCli.UpdateById(domain.CollectName(), Id, &domain)
	if err != nil {
		return err
	}
	return nil
}

func DeleteDomain(e *config.Env, Id string) error {
	var u model.Domain
	objId, err := primitive.ObjectIDFromHex(Id)
	if err != nil {
		return err
	}
	return e.MongoCli.RemoveById(u.CollectName(), objId)
}

func CheckDomain(env *config.Env, hostname, domainName string) (*model.Domain, error) {
	domain := &model.Domain{}

	tb := domain.CollectName()
	query := bson.D{{Key: "name", Value: primitive.Regex{Pattern: domainName, Options: "i"}}, {Key: "dc_hostname", Value: primitive.Regex{Pattern: hostname, Options: "i"}}}

	err, _ := env.MongoCli.FindOne(tb, query, &domain)
	if err != nil {
		return nil, err
	}
	return domain, nil
}

func GetPwdByLdapAddr(e *config.Env, ldapAddr string) (*model.Domain, error) {
	domain := &model.Domain{}

	ldapInfo, err := url.Parse(ldapAddr)
	if err != nil {
		logger.Errorf("parse ladpAddr err:%v", err)
		return nil, err
	}
	FQDN := ldapInfo.Host
	dcHostNameList := strings.Split(FQDN, ".")
	domainName := strings.Join(dcHostNameList[1:], ".")

	query := bson.M{"name": domainName}

	err, _ = e.MongoCli.FindOne(domain.CollectName(), query, &domain)
	if err != nil {
		logger.Errorf("find domain info by name err:%v", err)
		return nil, err
	}

	return domain, nil
}

// UpdateDCHasSensor updates the HasSensor status of a specific DC in a domain
func UpdateDCHasSensor(e *config.Env, domainID, dcHostname string, hasSensor bool) error {
	domain, err := GetDomainById(e, domainID)
	if err != nil {
		return err
	}

	updated := false
	for i, dc := range domain.DCList {
		if dc.HostName == dcHostname {
			domain.DCList[i].HasSensor = hasSensor
			updated = true
			break
		}
	}

	if !updated {
		return fmt.Errorf("DC hostname %s not found in domain", dcHostname)
	}

	objId, err := primitive.ObjectIDFromHex(domainID)
	if err != nil {
		return err
	}

	return e.MongoCli.UpdateById(domain.CollectName(), objId, domain)
}

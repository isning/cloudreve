package oidc

import (
	"fmt"
	"github.com/tidwall/gjson"
	"net/mail"
	"strings"
	"unicode/utf8"
)

type Profile struct {
	Email, Name, Avatar string
	GroupID             int
}

func profileValue(claims []byte, mapping, fallback string) string {
	if mapping == "" {
		mapping = fallback
	}
	return gjson.GetBytes(claims, mapping).String()
}
func mappedProfile(p Provider, profile *verifiedProfile, defaultGroup int) (Profile, error) {
	email := strings.TrimSpace(profileValue(profile.Claims, p.Config.EmailMapping, "email"))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 100 || !strings.Contains(email, "@") {
		return Profile{}, fmt.Errorf("provider email is missing or invalid; create a local account and associate this identity explicitly")
	}
	name := strings.TrimSpace(profileValue(profile.Claims, p.Config.NameMapping, "name"))
	if name == "" {
		name = strings.Split(email, "@")[0]
	}
	for len(name) > 100 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	avatar := profileValue(profile.Claims, p.Config.AvatarMapping, "picture")
	if avatar != "" && !validEndpoint(avatar) {
		avatar = ""
	}
	group := defaultGroup
	if p.Config.GroupMappingField != "" {
		value := gjson.GetBytes(profile.Claims, p.Config.GroupMappingField)
		if value.IsArray() || value.IsObject() {
			return Profile{}, fmt.Errorf("initial group mapping requires a scalar claim")
		}
		if mapped, ok := p.Config.GroupMapping[value.String()]; ok {
			group = mapped
		}
	}
	if group <= 0 {
		return Profile{}, fmt.Errorf("invalid default account group")
	}
	return Profile{Email: email, Name: name, Avatar: avatar, GroupID: group}, nil
}

package controllers

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	userService "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"strings"
)

func openIDError(c *gin.Context, err error) {
	// These endpoints reject an external operation, not the caller's native
	// session. CredentialInvalid makes the existing client sign out that session.
	c.JSON(200, serializer.Err(c, serializer.NewError(serializer.CodeParamErr, err.Error(), nil)))
}
func openIDCookieName(state string) string { return "cr_oidc_" + state }
func BeginOpenID(c *gin.Context) {
	var input struct {
		Provider *int   `json:"provider" binding:"required,gte=0"`
		Hint     string `json:"hint"`
		Linking  bool   `json:"linking"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		openIDError(c, fmt.Errorf("invalid OpenID request"))
		return
	}
	request := oidc.PrepareRequest{Provider: *input.Provider, Hint: input.Hint, Linking: input.Linking}
	if request.Linking {
		u := inventory.UserFromContext(c)
		if u == nil || u.ID == 0 {
			openIDError(c, fmt.Errorf("sign in locally before associating an identity"))
			return
		}
		request.UserID = u.ID
	}
	result, err := dependency.FromContext(c).OIDC().Prepare(c.Request.Context(), request)
	if err != nil {
		openIDError(c, err)
		return
	}
	secure := dependency.FromContext(c).SettingProvider().SiteURL(c.Request.Context()).Scheme == "https"
	// A separate cookie per state supports independent tabs and binding intents.
	http.SetCookie(c.Writer, &http.Cookie{Name: openIDCookieName(result.State), Value: result.Proof, Path: "/api/v4/session", MaxAge: 600, Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	c.JSON(200, serializer.Response{Data: result.URL})
}

func FinishOpenID(c *gin.Context) {
	var input struct {
		ProviderID *int   `json:"provider_id" binding:"required,gte=0"`
		Code       string `json:"code" binding:"required"`
		SessionID  string `json:"session_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		openIDError(c, fmt.Errorf("invalid OpenID callback"))
		return
	}
	request := oidc.FinishRequest{ProviderID: *input.ProviderID, Code: input.Code, SessionID: input.SessionID}
	request.Proof, _ = c.Cookie(openIDCookieName(request.SessionID))
	dep := dependency.FromContext(c)
	if header := c.GetHeader(auth.AuthorizationHeader); strings.HasPrefix(header, auth.TokenHeaderPrefix) {
		if claims, err := dep.TokenAuth().Claims(c.Request.Context(), strings.TrimPrefix(header, auth.TokenHeaderPrefix)); err == nil && claims.TokenType == auth.TokenTypeAccess {
			if uid, err := dep.HashIDEncoder().Decode(claims.Subject, hashid.UserID); err == nil {
				if u, err := dep.UserClient().GetActiveByID(c.Request.Context(), uid); err == nil {
					request.AuthenticatedUserID = u.ID
				}
			}
		}
	}

	result, err := dependency.FromContext(c).OIDC().Finish(c.Request.Context(), request)
	if err != nil {
		openIDError(c, err)
		return
	}
	if result.Challenge != "" {
		secure := dep.SettingProvider().SiteURL(c.Request.Context()).Scheme == "https"
		http.SetCookie(c.Writer, &http.Cookie{Name: openIDCookieName(result.Challenge), Value: request.Proof, Path: "/api/v4/session", MaxAge: 300, Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		c.JSON(200, serializer.Response{Code: serializer.CodeNotFullySuccess, Data: result.Challenge})
		return
	}
	if result.Linked {
		c.JSON(200, serializer.Response{})
		return
	}
	writeOpenIDLogin(c, result)
}
func writeOpenIDLogin(c *gin.Context, result *oidc.FinishResult) {
	dep := dependency.FromContext(c)
	u, err := dep.UserClient().GetActiveByID(context.WithValue(c.Request.Context(), inventory.LoadUserGroup{}, true), result.UserID)
	if err != nil {
		openIDError(c, fmt.Errorf("account is unavailable"))
		return
	}
	c.JSON(200, serializer.Response{Data: struct {
		User  userService.User `json:"user"`
		Token *oidc.Token      `json:"token"`
	}{userService.BuildUser(u, dep.HashIDEncoder()), result.Token}})
}

func UnlinkOpenID(c *gin.Context) {
	u := inventory.UserFromContext(c)
	if u == nil || u.ID <= 0 {
		openIDError(c, fmt.Errorf("sign in first"))
		return
	}
	provider, err := strconv.Atoi(c.Param("provider_id"))
	if err != nil || provider < 0 {
		openIDError(c, fmt.Errorf("invalid provider identifier"))
		return
	}
	if err = dependency.FromContext(c).OIDC().Unlink(c.Request.Context(), u.ID, provider); err != nil {
		openIDError(c, err)
		return
	}
	c.JSON(200, serializer.Response{})
}

func ReleaseManagedAccount(c *gin.Context) {
	uid, err := strconv.Atoi(c.Param("id"))
	if err != nil || uid <= 0 {
		openIDError(c, fmt.Errorf("invalid account identifier"))
		return
	}
	if err = inventory.ReleaseManagedAccount(c.Request.Context(), dependency.FromContext(c).DBClient(), uid); err != nil {
		openIDError(c, err)
		return
	}
	c.JSON(200, serializer.Response{})
}

func DiscoverOpenID(c *gin.Context) {
	document, err := dependency.FromContext(c).OIDC().Discovery(c.Request.Context(), c.Query("endpoint"))
	if err != nil {
		openIDError(c, err)
		return
	}
	c.JSON(200, serializer.Response{Data: document})
}

func OpenIDCallbackURI(c *gin.Context) {
	provider, err := strconv.Atoi(c.Param("provider_id"))
	if err != nil || provider < 0 {
		openIDError(c, fmt.Errorf("invalid provider identifier"))
		return
	}
	callback, err := dependency.FromContext(c).OIDC().CallbackURL(c.Request.Context(), provider)
	if err != nil {
		openIDError(c, err)
		return
	}
	c.JSON(200, serializer.Response{Data: callback})
}

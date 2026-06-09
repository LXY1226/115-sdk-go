// docs: https://www.yuque.com/115yun/open/shtpzfhewv5nag11
package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"
)

type AuthDeviceCodeResp struct {
	UID    string `json:"uid"`
	Time   int64  `json:"time"`
	QrCode string `json:"qrcode"`
	Sign   string `json:"sign"`
}

// $code_challenge = base64_encode(sha256($code_verifier));
func calCodeChanllenge(codeVerifier string) string {
	sha := sha256.New()
	sha.Write([]byte(codeVerifier))
	return base64.StdEncoding.EncodeToString(sha.Sum(nil))
}

func (c *Client) AuthDeviceCode(ctx context.Context, clientID string, codeVerifier string) (*AuthDeviceCodeResp, error) {
	var resp AuthDeviceCodeResp
	_, err := c.passportRequest(ctx, ApiAuthDeviceCode, http.MethodPost, &resp, ReqWithForm(Form{
		"client_id":             clientID,
		"code_challenge":        calCodeChanllenge(codeVerifier),
		"code_challenge_method": "sha256",
	}))
	if err != nil {
		return nil, err
	}
	return &resp, err
}

type QrCodeStatusResp struct {
	Msg     string `json:"msg"`
	Status  int    `json:"status"`
	Version string `json:"version"`
}

func (c *Client) QrCodeStatus(ctx context.Context, uid, time, sign string) (*QrCodeStatusResp, error) {
	var resp QrCodeStatusResp
	_, err := c.passportRequest(ctx, ApiQrCodeStatus, http.MethodGet, &resp, ReqWithQuery(Form{
		"uid":  uid,
		"time": time,
		"sign": sign,
	}))
	if err != nil {
		return nil, err
	}
	return &resp, err
}

type CodeToTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (c *Client) CodeToToken(ctx context.Context, uid, codeVerifier string) (*CodeToTokenResp, error) {
	var resp CodeToTokenResp
	_, err := c.passportRequest(ctx, ApiCodeToToken, http.MethodPost, &resp, ReqWithForm(Form{
		"uid":           uid,
		"code_verifier": codeVerifier,
	}))
	if err != nil {
		return nil, err
	}
	// TODO: set token?
	c.SetAccessToken(resp.AccessToken)
	c.SetRefreshToken(resp.RefreshToken)
	return &resp, err
}

type RefreshTokenResp CodeToTokenResp

func (c *Client) RefreshToken(ctx context.Context) (*RefreshTokenResp, error) {
	token, err := c.getRefreshToken(ctx)
	if err != nil {
		return nil, err
	}
	c.SetAccessToken(token.AccessToken)
	c.SetRefreshToken(token.RefreshToken)
	if c.onRefreshToken != nil {
		c.onRefreshToken(token.AccessToken, token.RefreshToken)
	}
	return &RefreshTokenResp{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    token.ExpiresIn,
	}, nil
}

func (c *Client) getRefreshToken(ctx context.Context) (TokenValue, error) {
	if c.beforeRefresh != nil {
		token, err := c.beforeRefresh(ctx, TokenValue{
			AccessToken:  c.accessToken,
			RefreshToken: c.refreshToken,
		})
		if err != nil {
			return TokenValue{}, err
		}
		if token != nil {
			return *token, nil
		}
	}
	var resp RefreshTokenResp
	_, err := c.passportRequest(ctx, ApiRefreshToken, http.MethodPost, &resp, ReqWithForm(Form{
		"refresh_token": c.refreshToken,
	}))
	if err != nil {
		return TokenValue{}, err
	}
	token := TokenValue{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
	}.WithRefreshTime(time.Now())
	return token, nil
}

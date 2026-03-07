package errors

import (
	"net/http"

	"github.com/KOMKZ/go-yogan-framework/errcode"
)

const ModuleAuth = 33

var (
	ErrInvalidCredentials = errcode.Register(errcode.New(
		ModuleAuth, 1001, "auth",
		"error.auth.invalid_credentials", "用户名或密码错误",
		http.StatusUnauthorized,
	))
	ErrUserNotFound = errcode.Register(errcode.New(
		ModuleAuth, 1002, "auth",
		"error.auth.user_not_found", "用户不存在",
		http.StatusNotFound,
	))
	ErrTokenExpired = errcode.Register(errcode.New(
		ModuleAuth, 1003, "auth",
		"error.auth.token_expired", "令牌已过期",
		http.StatusUnauthorized,
	))
	ErrTokenInvalid = errcode.Register(errcode.New(
		ModuleAuth, 1004, "auth",
		"error.auth.token_invalid", "令牌无效",
		http.StatusUnauthorized,
	))
	ErrUnauthorized = errcode.Register(errcode.New(
		ModuleAuth, 1005, "auth",
		"error.auth.unauthorized", "未授权",
		http.StatusUnauthorized,
	))
)

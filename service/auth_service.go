package service

import (
	"context"

	auth "github.com/KOMKZ/go-yogan-domain-auth"
	autherrors "github.com/KOMKZ/go-yogan-domain-auth/errors"
	"github.com/KOMKZ/go-yogan-framework/logger"
	"go.uber.org/zap"
)

type AuthService struct {
	userProvider   auth.UserProvider
	passwordHasher auth.PasswordHasher
	logger         *logger.CtxZapLogger
}

func NewAuthService(userProvider auth.UserProvider, passwordHasher auth.PasswordHasher, log *logger.CtxZapLogger) *AuthService {
	return &AuthService{
		userProvider:   userProvider,
		passwordHasher: passwordHasher,
		logger:         log,
	}
}

type LoginResult struct {
	UserID uint
	Email  string
}

// Login 验证凭证（email + password），不包含业务状态检查（如禁用），业务状态由调用方处理
// 系统错误（如 DB 故障）原样返回，仅凭证无效时返回 ErrInvalidCredentials
func (s *AuthService) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	user, err := s.userProvider.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, autherrors.ErrInvalidCredentials
	}

	if !s.passwordHasher.Verify(password, user.GetPasswordHash()) {
		s.logger.WarnCtx(ctx, "login failed: invalid password", zap.String("email", email))
		return nil, autherrors.ErrInvalidCredentials
	}

	s.logger.InfoCtx(ctx, "login success", zap.Uint("user_id", user.GetID()), zap.String("email", email))
	return &LoginResult{
		UserID: user.GetID(),
		Email:  user.GetEmail(),
	}, nil
}

// GetUserByID 通过 ID 获取可认证用户
// 系统错误原样返回，仅用户确实不存在时返回 ErrUserNotFound
func (s *AuthService) GetUserByID(ctx context.Context, id uint) (auth.Authenticatable, error) {
	user, err := s.userProvider.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, autherrors.ErrUserNotFound
	}
	return user, nil
}

// ValidateUser 检查用户是否存在
func (s *AuthService) ValidateUser(ctx context.Context, id uint) (bool, error) {
	user, err := s.userProvider.FindByID(ctx, id)
	if err != nil {
		return false, err
	}
	return user != nil, nil
}

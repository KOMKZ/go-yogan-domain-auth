package service

import (
	"context"

	auth "github.com/KOMKZ/go-yogan-domain-auth"
	autherrors "github.com/KOMKZ/go-yogan-domain-auth/errors"
)

type AuthService struct {
	userProvider   auth.UserProvider
	passwordHasher auth.PasswordHasher
}

func NewAuthService(userProvider auth.UserProvider, passwordHasher auth.PasswordHasher) *AuthService {
	return &AuthService{
		userProvider:   userProvider,
		passwordHasher: passwordHasher,
	}
}

type LoginResult struct {
	UserID uint
	Email  string
}

// Login 验证凭证（email + password），不包含业务状态检查（如禁用），业务状态由调用方处理
func (s *AuthService) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	user, err := s.userProvider.FindByEmail(ctx, email)
	if err != nil {
		return nil, autherrors.ErrInvalidCredentials
	}
	if user == nil {
		return nil, autherrors.ErrInvalidCredentials
	}

	if !s.passwordHasher.Verify(password, user.GetPasswordHash()) {
		return nil, autherrors.ErrInvalidCredentials
	}

	return &LoginResult{
		UserID: user.GetID(),
		Email:  user.GetEmail(),
	}, nil
}

// GetUserByID 通过 ID 获取可认证用户
func (s *AuthService) GetUserByID(ctx context.Context, id uint) (auth.Authenticatable, error) {
	user, err := s.userProvider.FindByID(ctx, id)
	if err != nil {
		return nil, autherrors.ErrUserNotFound
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

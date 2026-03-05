package auth

import "context"

// UserProvider 用户提供者接口
// 应用层注入具体实现（AdminRepository 或 MemberRepository）
type UserProvider interface {
	FindByID(ctx context.Context, id uint) (Authenticatable, error)
	FindByEmail(ctx context.Context, email string) (Authenticatable, error)
}

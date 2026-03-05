package auth

// Authenticatable 可认证实体接口
// admin 和 member 的 model 都应实现此接口
type Authenticatable interface {
	GetID() uint
	GetEmail() string
	GetPasswordHash() string
}

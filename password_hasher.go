package auth

import "golang.org/x/crypto/bcrypt"

// PasswordHasher 密码哈希接口
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

// BcryptHasher bcrypt 密码哈希实现
type BcryptHasher struct {
	cost int
}

func NewBcryptHasher() *BcryptHasher {
	return &BcryptHasher{cost: bcrypt.DefaultCost}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	return string(bytes), err
}

func (h *BcryptHasher) Verify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

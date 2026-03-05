package service

import (
	"context"
	"errors"
	"testing"

	auth "github.com/KOMKZ/go-yogan-domain-auth"
	autherrors "github.com/KOMKZ/go-yogan-domain-auth/errors"
)

// mockUser implements auth.Authenticatable
type mockUser struct {
	id       uint
	email    string
	passHash string
}

func (m *mockUser) GetID() uint              { return m.id }
func (m *mockUser) GetEmail() string         { return m.email }
func (m *mockUser) GetPasswordHash() string  { return m.passHash }

// mockUserProvider implements auth.UserProvider
type mockUserProvider struct {
	users map[string]*mockUser
	byID  map[uint]*mockUser
	err   error
}

func newMockUserProvider() *mockUserProvider {
	return &mockUserProvider{
		users: make(map[string]*mockUser),
		byID:  make(map[uint]*mockUser),
	}
}

func (m *mockUserProvider) addUser(u *mockUser) {
	m.users[u.email] = u
	m.byID[u.id] = u
}

func (m *mockUserProvider) FindByEmail(ctx context.Context, email string) (auth.Authenticatable, error) {
	if m.err != nil {
		return nil, m.err
	}
	if u, ok := m.users[email]; ok {
		return u, nil
	}
	return nil, nil
}

func (m *mockUserProvider) FindByID(ctx context.Context, id uint) (auth.Authenticatable, error) {
	if m.err != nil {
		return nil, m.err
	}
	if u, ok := m.byID[id]; ok {
		return u, nil
	}
	return nil, nil
}

// mockPasswordHasher implements auth.PasswordHasher
type mockPasswordHasher struct {
	shouldVerify bool
	hashResult   string
	hashErr      error
}

func (m *mockPasswordHasher) Hash(password string) (string, error) {
	if m.hashErr != nil {
		return "", m.hashErr
	}
	if m.hashResult != "" {
		return m.hashResult, nil
	}
	return "mock_hash_" + password, nil
}

func (m *mockPasswordHasher) Verify(password, hash string) bool {
	return m.shouldVerify
}

func TestNewAuthService(t *testing.T) {
	provider := newMockUserProvider()
	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)
	if svc == nil {
		t.Fatal("NewAuthService returned nil")
	}
}

func TestAuthService_Login_Success(t *testing.T) {
	provider := newMockUserProvider()
	user := &mockUser{id: 1, email: "test@example.com", passHash: "hashed"}
	provider.addUser(user)

	hasher := &mockPasswordHasher{shouldVerify: true}
	svc := NewAuthService(provider, hasher)

	result, err := svc.Login(context.Background(), "test@example.com", "password")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result == nil {
		t.Fatal("Login() returned nil result")
	}
	if result.UserID != 1 {
		t.Errorf("UserID = %d, want 1", result.UserID)
	}
	if result.Email != "test@example.com" {
		t.Errorf("Email = %s, want test@example.com", result.Email)
	}
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	provider := newMockUserProvider()
	hasher := &mockPasswordHasher{shouldVerify: true}
	svc := NewAuthService(provider, hasher)

	_, err := svc.Login(context.Background(), "nonexistent@example.com", "password")
	if err != autherrors.ErrInvalidCredentials {
		t.Errorf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthService_Login_FindByEmailReturnsError(t *testing.T) {
	provider := newMockUserProvider()
	dbErr := errors.New("db error")
	provider.err = dbErr
	hasher := &mockPasswordHasher{shouldVerify: true}
	svc := NewAuthService(provider, hasher)

	_, err := svc.Login(context.Background(), "test@example.com", "password")
	if err != dbErr {
		t.Errorf("Login() error = %v, want original db error", err)
	}
}

func TestAuthService_Login_FindByEmailReturnsNil(t *testing.T) {
	provider := newMockUserProvider()
	// Don't add any users - FindByEmail returns (nil, nil) for unknown email
	hasher := &mockPasswordHasher{shouldVerify: true}
	svc := NewAuthService(provider, hasher)

	_, err := svc.Login(context.Background(), "unknown@example.com", "password")
	if err != autherrors.ErrInvalidCredentials {
		t.Errorf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthService_Login_PasswordMismatch(t *testing.T) {
	provider := newMockUserProvider()
	user := &mockUser{id: 1, email: "test@example.com", passHash: "hashed"}
	provider.addUser(user)

	hasher := &mockPasswordHasher{shouldVerify: false}
	svc := NewAuthService(provider, hasher)

	_, err := svc.Login(context.Background(), "test@example.com", "wrongpassword")
	if err != autherrors.ErrInvalidCredentials {
		t.Errorf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthService_GetUserByID_Success(t *testing.T) {
	provider := newMockUserProvider()
	user := &mockUser{id: 42, email: "user@example.com", passHash: "hash"}
	provider.addUser(user)

	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	got, err := svc.GetUserByID(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByID() returned nil user")
	}
	if got.GetID() != 42 {
		t.Errorf("GetID() = %d, want 42", got.GetID())
	}
	if got.GetEmail() != "user@example.com" {
		t.Errorf("GetEmail() = %s, want user@example.com", got.GetEmail())
	}
}

func TestAuthService_GetUserByID_UserNotFound(t *testing.T) {
	provider := newMockUserProvider()
	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	_, err := svc.GetUserByID(context.Background(), 999)
	if err != autherrors.ErrUserNotFound {
		t.Errorf("GetUserByID() error = %v, want ErrUserNotFound", err)
	}
}

func TestAuthService_GetUserByID_FindByIDReturnsError(t *testing.T) {
	provider := newMockUserProvider()
	dbErr := errors.New("db error")
	provider.err = dbErr
	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	_, err := svc.GetUserByID(context.Background(), 1)
	if err != dbErr {
		t.Errorf("GetUserByID() error = %v, want original db error", err)
	}
}

func TestAuthService_GetUserByID_FindByIDReturnsNil(t *testing.T) {
	provider := newMockUserProvider()
	// Empty provider, FindByID returns (nil, nil)
	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	_, err := svc.GetUserByID(context.Background(), 1)
	if err != autherrors.ErrUserNotFound {
		t.Errorf("GetUserByID() error = %v, want ErrUserNotFound", err)
	}
}

func TestAuthService_ValidateUser_Success(t *testing.T) {
	provider := newMockUserProvider()
	user := &mockUser{id: 1, email: "a@b.com", passHash: "x"}
	provider.addUser(user)

	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	ok, err := svc.ValidateUser(context.Background(), 1)
	if err != nil {
		t.Fatalf("ValidateUser() error = %v", err)
	}
	if !ok {
		t.Error("ValidateUser() = false, want true")
	}
}

func TestAuthService_ValidateUser_UserNotFound(t *testing.T) {
	provider := newMockUserProvider()
	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	ok, err := svc.ValidateUser(context.Background(), 999)
	if err != nil {
		t.Fatalf("ValidateUser() error = %v", err)
	}
	if ok {
		t.Error("ValidateUser() = true, want false")
	}
}

func TestAuthService_ValidateUser_ProviderError(t *testing.T) {
	provider := newMockUserProvider()
	provider.err = errors.New("db connection failed")
	hasher := &mockPasswordHasher{}
	svc := NewAuthService(provider, hasher)

	ok, err := svc.ValidateUser(context.Background(), 1)
	if err == nil {
		t.Fatal("ValidateUser() expected error, got nil")
	}
	if ok {
		t.Error("ValidateUser() = true when error occurred, want false")
	}
	if !errors.Is(err, provider.err) && err.Error() != "db connection failed" {
		t.Errorf("ValidateUser() error = %v", err)
	}
}

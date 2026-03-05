package providerdo

import (
	"context"
	"testing"

	auth "github.com/KOMKZ/go-yogan-domain-auth"
	"github.com/KOMKZ/go-yogan-domain-auth/service"
	"github.com/samber/do/v2"
)

// providerMockUser implements auth.Authenticatable for provider tests
type providerMockUser struct {
	id       uint
	email    string
	passHash string
}

func (m *providerMockUser) GetID() uint             { return m.id }
func (m *providerMockUser) GetEmail() string        { return m.email }
func (m *providerMockUser) GetPasswordHash() string { return m.passHash }

// providerMockUserProvider implements auth.UserProvider
type providerMockUserProvider struct {
	users map[uint]*providerMockUser
}

func newProviderMockUserProvider(i do.Injector) (auth.UserProvider, error) {
	m := &providerMockUserProvider{users: make(map[uint]*providerMockUser)}
	m.users[1] = &providerMockUser{id: 1, email: "admin@test.com", passHash: "hashed"}
	return m, nil
}

func (m *providerMockUserProvider) FindByID(ctx context.Context, id uint) (auth.Authenticatable, error) {
	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, nil
}

func (m *providerMockUserProvider) FindByEmail(ctx context.Context, email string) (auth.Authenticatable, error) {
	for _, u := range m.users {
		if u.email == email {
			return u, nil
		}
	}
	return nil, nil
}

func TestProvideBcryptHasher(t *testing.T) {
	injector := do.New()
	do.Provide(injector, ProvideBcryptHasher)

	hasher, err := do.Invoke[auth.PasswordHasher](injector)
	if err != nil {
		t.Fatalf("Invoke PasswordHasher: %v", err)
	}
	if hasher == nil {
		t.Fatal("PasswordHasher is nil")
	}
	hash, err := hasher.Hash("test")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !hasher.Verify("test", hash) {
		t.Error("Verify failed for correct password")
	}
}

func TestProvideAuthService(t *testing.T) {
	injector := do.New()
	do.Provide(injector, newProviderMockUserProvider)
	do.Provide(injector, ProvideBcryptHasher)
	do.Provide(injector, ProvideAuthService)

	svc, err := do.Invoke[*service.AuthService](injector)
	if err != nil {
		t.Fatalf("Invoke AuthService: %v", err)
	}
	if svc == nil {
		t.Fatal("AuthService is nil")
	}
	// Quick sanity: GetUserByID with our mock user
	user, err := svc.GetUserByID(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if user.GetEmail() != "admin@test.com" {
		t.Errorf("GetEmail() = %s, want admin@test.com", user.GetEmail())
	}
}

func TestProvideAuthService_MissingUserProvider(t *testing.T) {
	injector := do.New()
	do.Provide(injector, ProvideBcryptHasher)
	do.Provide(injector, ProvideAuthService)

	_, err := do.Invoke[*service.AuthService](injector)
	if err == nil {
		t.Fatal("expected error when UserProvider not provided")
	}
}

func TestProvideAuthService_MissingPasswordHasher(t *testing.T) {
	injector := do.New()
	do.Provide(injector, newProviderMockUserProvider)
	do.Provide(injector, ProvideAuthService)

	_, err := do.Invoke[*service.AuthService](injector)
	if err == nil {
		t.Fatal("expected error when PasswordHasher not provided")
	}
}

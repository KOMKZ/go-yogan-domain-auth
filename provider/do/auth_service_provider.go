package providerdo

import (
	auth "github.com/KOMKZ/go-yogan-domain-auth"
	"github.com/KOMKZ/go-yogan-domain-auth/service"
	"github.com/samber/do/v2"
)

func ProvideAuthService(i do.Injector) (*service.AuthService, error) {
	userProvider, err := do.Invoke[auth.UserProvider](i)
	if err != nil {
		return nil, err
	}
	passwordHasher, err := do.Invoke[auth.PasswordHasher](i)
	if err != nil {
		return nil, err
	}
	return service.NewAuthService(userProvider, passwordHasher), nil
}

func ProvideBcryptHasher(i do.Injector) (auth.PasswordHasher, error) {
	return auth.NewBcryptHasher(), nil
}

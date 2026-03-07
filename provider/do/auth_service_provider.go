package do

import (
	auth "github.com/KOMKZ/go-yogan-domain-auth"
	"github.com/KOMKZ/go-yogan-domain-auth/service"
	"github.com/KOMKZ/go-yogan-framework/logger"
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
	log := do.MustInvokeNamed[*logger.CtxZapLogger](i, "auth")
	return service.NewAuthService(userProvider, passwordHasher, log), nil
}

func ProvideBcryptHasher(i do.Injector) (auth.PasswordHasher, error) {
	return auth.NewBcryptHasher(), nil
}

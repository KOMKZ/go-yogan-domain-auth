package errors

import "testing"

func TestErrorValues(t *testing.T) {
	if ErrInvalidCredentials == nil {
		t.Fatal("ErrInvalidCredentials should not be nil")
	}
	if ErrUserNotFound == nil {
		t.Fatal("ErrUserNotFound should not be nil")
	}
	if ErrTokenExpired == nil {
		t.Fatal("ErrTokenExpired should not be nil")
	}
	if ErrTokenInvalid == nil {
		t.Fatal("ErrTokenInvalid should not be nil")
	}
	if ErrUnauthorized == nil {
		t.Fatal("ErrUnauthorized should not be nil")
	}
}

func TestErrorMessages(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrInvalidCredentials, "invalid credentials"},
		{ErrUserNotFound, "user not found"},
		{ErrTokenExpired, "token expired"},
		{ErrTokenInvalid, "token invalid"},
		{ErrUnauthorized, "unauthorized"},
	}
	for _, c := range cases {
		if c.err.Error() != c.want {
			t.Errorf("expected %q, got %q", c.want, c.err.Error())
		}
	}
}

package service

import "time"

const (
	minProactiveRefreshWindow = 60 * time.Second
	maxProactiveRefreshRatio  = 2
	defaultAccessTokenTTL     = 2 * time.Hour
)

type TokenPolicyService struct {
	accessTokenTTL  time.Duration
	refreshAheadFor time.Duration
}

func NewTokenPolicyService(accessTokenTTL time.Duration) *TokenPolicyService {
	if accessTokenTTL <= 0 {
		accessTokenTTL = defaultAccessTokenTTL
	}

	refreshAhead := accessTokenTTL / 6
	if refreshAhead < minProactiveRefreshWindow {
		refreshAhead = minProactiveRefreshWindow
	}
	maxRefreshAhead := accessTokenTTL / maxProactiveRefreshRatio
	if refreshAhead > maxRefreshAhead {
		refreshAhead = maxRefreshAhead
	}

	return &TokenPolicyService{
		accessTokenTTL:  accessTokenTTL,
		refreshAheadFor: refreshAhead,
	}
}

func (s *TokenPolicyService) AccessTokenTTLSeconds() int64 {
	return int64(s.accessTokenTTL.Seconds())
}

func (s *TokenPolicyService) ProactiveRefreshAfterSeconds() int64 {
	refreshAfter := s.accessTokenTTL - s.refreshAheadFor
	if refreshAfter < minProactiveRefreshWindow {
		refreshAfter = minProactiveRefreshWindow
	}
	return int64(refreshAfter.Seconds())
}

func (s *TokenPolicyService) ShouldRefreshBefore(expireAt time.Time, now time.Time) bool {
	if expireAt.IsZero() {
		return false
	}
	return expireAt.Sub(now) <= s.refreshAheadFor
}

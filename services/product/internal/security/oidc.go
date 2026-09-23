package security

import (
	"context"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCAuthorizer struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCAuthorizer(ctx context.Context, issuer, audience string) (*OIDCAuthorizer, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, errors.New("OIDC issuer and audience are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &OIDCAuthorizer{verifier: provider.Verifier(&oidc.Config{ClientID: audience})}, nil
}

func (a *OIDCAuthorizer) Authorize(ctx context.Context, authorization string) error {
	scheme, token, found := strings.Cut(strings.TrimSpace(authorization), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return errors.New("bearer token required")
	}
	_, err := a.verifier.Verify(ctx, strings.TrimSpace(token))
	return err
}

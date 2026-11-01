package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/tacenva/tacenva-core/auth"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
)

type contextKey string

const authorizedUserKey contextKey = "auth-user"

type Auth struct {
	authService *auth.Service
}

func NewAuth(
	authService *auth.Service,
) *Auth {
	return &Auth{
		authService: authService,
	}
}

func (m *Auth) Authenticate(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			authHeader := r.Header.Get(
				"Authorization",
			)

			if authHeader == "" {
				http.Error(
					w,
					"authorization header is required",
					http.StatusUnauthorized,
				)
				return
			}

			const bearerPrefix = "Bearer "

			if !strings.HasPrefix(
				authHeader,
				bearerPrefix,
			) {
				http.Error(
					w,
					"invalid authorization header",
					http.StatusUnauthorized,
				)
				return
			}

			token := strings.TrimSpace(
				strings.TrimPrefix(
					authHeader,
					bearerPrefix,
				),
			)

			if token == "" {
				http.Error(
					w,
					"bearer token is required",
					http.StatusUnauthorized,
				)
				return
			}

			authorizedUser, err := m.authService.GetUserData(
				token,
			)
			if err != nil {
				http.Error(
					w,
					err.Error(),
					http.StatusUnauthorized,
				)
				return
			}

			if authorizedUser == nil {
				http.Error(
					w,
					"unauthorized",
					http.StatusUnauthorized,
				)
				return
			}

			ctx := context.WithValue(
				r.Context(),
				authorizedUserKey,
				authorizedUser,
			)

			next.ServeHTTP(
				w,
				r.WithContext(ctx),
			)
		},
	)
}

func GetauthorizedUser(
	r *http.Request,
) *tacenvaentity.User {
	authorizedUser, _ := r.Context().Value(
		authorizedUserKey,
	).(*tacenvaentity.User)

	return authorizedUser
}

func WithauthorizedUser(
	r *http.Request,
	authorizedUser *tacenvaentity.User,
) *http.Request {
	ctx := context.WithValue(
		r.Context(),
		authorizedUserKey,
		authorizedUser,
	)

	return r.WithContext(ctx)
}

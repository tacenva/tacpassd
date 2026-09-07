package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
)

type contextKey string

const authUserKey contextKey = "auth-user"

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

			authUser, err := m.authService.GetUserData(
				token,
			)
			if err != nil {
				http.Error(
					w,
					"unauthorized",
					http.StatusUnauthorized,
				)
				return
			}

			if authUser.Status != entity.UserStatusApproved {
				http.Error(
					w,
					"user is not approved",
					http.StatusForbidden,
				)
				return
			}

			ctx := context.WithValue(
				r.Context(),
				authUserKey,
				authUser,
			)

			next.ServeHTTP(
				w,
				r.WithContext(ctx),
			)
		},
	)
}

func GetAuthUser(
	r *http.Request,
) *entity.User {
	authUser, _ := r.Context().Value(
		authUserKey,
	).(*entity.User)

	return authUser
}

func WithAuthUser(
	r *http.Request,
	authUser *entity.User,
) *http.Request {
	ctx := context.WithValue(
		r.Context(),
		authUserKey,
		authUser,
	)

	return r.WithContext(ctx)
}

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"
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

func debugAuth(
	format string,
	args ...any,
) {
	debugFile, err := os.OpenFile(
		"debug.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return
	}
	defer debugFile.Close()

	fmt.Fprintf(
		debugFile,
		format,
		args...,
	)

	fmt.Fprintln(debugFile)
}

func (m *Auth) Authenticate(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			debugAuth(
				"=== AUTH ===",
			)

			debugAuth(
				"Method: %s | Path: %s",
				r.Method,
				r.URL.Path,
			)

			authHeader := r.Header.Get(
				"Authorization",
			)

			debugAuth(
				"Authorization exists: %t",
				authHeader != "",
			)

			if authHeader == "" {
				debugAuth(
					"AUTH ERROR: authorization header is required",
				)

				http.Error(
					w,
					"authorization header is required",
					http.StatusUnauthorized,
				)
				return
			}

			const bearerPrefix = "Bearer "

			debugAuth(
				"Bearer prefix valid: %t",
				strings.HasPrefix(
					authHeader,
					bearerPrefix,
				),
			)

			if !strings.HasPrefix(
				authHeader,
				bearerPrefix,
			) {
				debugAuth(
					"AUTH ERROR: invalid authorization header",
				)

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

			debugAuth(
				"Token exists: %t | Token length: %d",
				token != "",
				len(token),
			)

			if token == "" {
				debugAuth(
					"AUTH ERROR: bearer token is required",
				)

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

			debugAuth(
				"GetUserData error: %v",
				err,
			)

			debugAuth(
				"AuthUser nil: %t",
				authUser == nil,
			)

			if authUser != nil {
				debugAuth(
					"AuthUser ID: %s | PermissionID: %s | Status: %s",
					authUser.ID,
					authUser.PermissionID,
					authUser.Status,
				)
			}

			if err != nil {
				debugAuth(
					"AUTH ERROR: GetUserData failed",
				)

				http.Error(
					w,
					err.Error(),
					http.StatusUnauthorized,
				)
				return
			}

			if authUser == nil {
				debugAuth(
					"AUTH ERROR: authUser is nil",
				)

				http.Error(
					w,
					"unauthorized",
					http.StatusUnauthorized,
				)
				return
			}

			debugAuth(
				"AUTH SUCCESS: user approved",
			)

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

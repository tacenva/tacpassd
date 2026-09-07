package server

import (
	"net/http"

	"github.com/tacenva/tacpassd/internal/feature/accesscontrol"
	"github.com/tacenva/tacpassd/internal/feature/auth"
	"github.com/tacenva/tacpassd/internal/feature/vault"
	"github.com/tacenva/tacpassd/internal/middleware"
)

func NewRouter(
	authMiddleware *middleware.Auth,
	authHandler *auth.Handler,
	accessControlHandler *accesscontrol.Handler,
	vaultHandler *vault.Handler,
) http.Handler {
	mux := http.NewServeMux()

	registerAuthRoutes(
		mux,
		authHandler,
	)

	registerAccessControlRoutes(
		mux,
		authMiddleware,
		accessControlHandler,
	)

	registerVaultRoutes(
		mux,
		authMiddleware,
		vaultHandler,
	)

	return mux
}

func registerAuthRoutes(
	mux *http.ServeMux,
	authHandler *auth.Handler,
) {
	mux.HandleFunc(
		"POST /auth/enroll",
		authHandler.Enroll,
	)
}

func registerVaultRoutes(
	mux *http.ServeMux,
	authMiddleware *middleware.Auth,
	vaultHandler *vault.Handler,
) {
	mux.Handle(
		"GET /vault/{vaultID}",
		authMiddleware.Authenticate(
			http.HandlerFunc(
				vaultHandler.GetVault,
			),
		),
	)

	mux.Handle(
		"POST /vault/{vaultID}/records",
		authMiddleware.Authenticate(
			http.HandlerFunc(
				vaultHandler.CreateRecord,
			),
		),
	)

	mux.Handle(
		"GET /vault/{vaultID}/records",
		authMiddleware.Authenticate(
			http.HandlerFunc(
				vaultHandler.GetAllRecord,
			),
		),
	)

	mux.Handle(
		"GET /vault/{vaultID}/records/{recordID}",
		authMiddleware.Authenticate(
			http.HandlerFunc(
				vaultHandler.GetRecord,
			),
		),
	)

	mux.Handle(
		"PUT /vault/{vaultID}/records/{recordID}",
		authMiddleware.Authenticate(
			http.HandlerFunc(
				vaultHandler.UpdateRecord,
			),
		),
	)

	mux.Handle(
		"DELETE /vault/{vaultID}/records/{recordID}",
		authMiddleware.Authenticate(
			http.HandlerFunc(
				vaultHandler.DeleteRecord,
			),
		),
	)
}

func registerAccessControlRoutes(
	mux *http.ServeMux,
	authMiddleware *middleware.Auth,
	handler *accesscontrol.Handler,
) {
	mux.Handle(
		"GET /access-control",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.List),
		),
	)

	mux.Handle(
		"GET /access-control/{id}",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.Get),
		),
	)

	mux.Handle(
		"POST /access-control",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.Create),
		),
	)

	mux.Handle(
		"PATCH /access-control/{id}/privilege",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.ChangePrivilege),
		),
	)

	mux.Handle(
		"DELETE /access-control/{id}",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.Revoke),
		),
	)

	mux.Handle(
		"GET /access-control/{id}/users",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.UserList),
		),
	)

	mux.Handle(
		"POST /access-control/users/{userId}/approve",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.ApproveUser),
		),
	)

	mux.Handle(
		"POST /access-control/users/{userId}/revoke",
		authMiddleware.Authenticate(
			http.HandlerFunc(handler.RevokeUser),
		),
	)
}

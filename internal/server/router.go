package server

import (
	"net/http"

	"github.com/tacenva/tacpassd/internal/feature/accesscontrol"
	"github.com/tacenva/tacpassd/internal/feature/auth"
	"github.com/tacenva/tacpassd/internal/feature/vault"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Router struct {
	mux            *http.ServeMux
	authMiddleware *middleware.Auth
}

func NewRouter(
	authMiddleware *middleware.Auth,
	authHandler *auth.Handler,
	accessControlHandler *accesscontrol.Handler,
	vaultHandler *vault.Handler,
) http.Handler {
	router := &Router{
		mux:            http.NewServeMux(),
		authMiddleware: authMiddleware,
	}

	router.registerAuthRoutes(authHandler)
	router.registerAccessControlRoutes(accessControlHandler)
	router.registerVaultRoutes(vaultHandler)

	return router.mux
}

func (r *Router) handle(
	pattern string,
	handler http.HandlerFunc,
) {
	r.mux.Handle(
		pattern,
		r.authMiddleware.Authenticate(handler),
	)
}

func (r *Router) registerAuthRoutes(
	handler *auth.Handler,
) {
	r.mux.HandleFunc(
		"POST /auth/enroll",
		handler.Enroll,
	)
}

func (r *Router) registerVaultRoutes(
	handler *vault.Handler,
) {
	r.handle(
		"POST /vault",
		handler.CreateVault,
	)
	r.handle(
		"POST /vault/sync/check",
		handler.CheckVaultSync,
	)

	r.handle(
		"POST /vault/sync",
		handler.VaultSync,
	)

	r.handle(
		"PUT /vault/{vaultID}",
		handler.UpdateVault,
	)

	r.handle(
		"DELETE /vault/{vaultID}",
		handler.DeleteVault,
	)

	r.handle(
		"POST /vault/{vaultID}/record",
		handler.CreateRecord,
	)

	r.handle(
		"POST /vault/{vaultID}/record/blob/check",
		handler.CheckRecordBlob,
	)

	r.handle(
		"POST /vault/{vaultID}/record/blob",
		handler.RecordBlob,
	)

	r.handle(
		"PUT /vault/{vaultID}/record/{recordID}",
		handler.UpdateRecord,
	)

	r.handle(
		"DELETE /vault/{vaultID}/record/{recordID}",
		handler.DeleteRecord,
	)
}

func (r *Router) registerAccessControlRoutes(
	handler *accesscontrol.Handler,
) {
	r.handle(
		"GET /access-control",
		handler.List,
	)

	r.handle(
		"GET /access-control/{id}",
		handler.Get,
	)

	r.handle(
		"POST /access-control",
		handler.Create,
	)

	r.handle(
		"PATCH /access-control/{id}/name",
		handler.ChangeName,
	)

	r.handle(
		"PATCH /access-control/{id}/privilege",
		handler.ChangePrivilege,
	)

	r.handle(
		"DELETE /access-control/{id}",
		handler.Revoke,
	)

	r.handle(
		"GET /access-control/{id}/users",
		handler.UserList,
	)

	r.handle(
		"POST /access-control/users/{userId}/approve",
		handler.ApproveUser,
	)

	r.handle(
		"POST /access-control/users/{userId}/revoke",
		handler.RevokeUser,
	)
}

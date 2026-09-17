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
		"GET /vault",
		handler.ListVault,
	)

	r.handle(
		"PUT /vault/{vaultID}",
		handler.UpdateVault,
	)

	r.handle(
		"DELETE /vault/{vaultID}",
		handler.DeleteVault,
	)

	// Vault sync

	r.handle(
		"GET /vault/changes/count",
		handler.PendingVaultCount,
	)

	r.handle(
		"GET /vault/changes",
		handler.GetPendingVaultChanges,
	)

	r.handle(
		"POST /vault/changes/synced",
		handler.MarkVaultChangesSynced,
	)

	// Vault access

	r.handle(
		"GET /vault/{vaultID}/accessible",
		handler.CheckVaultAccessible,
	)

	// Record

	r.handle(
		"POST /vault/{vaultID}/record",
		handler.CreateRecord,
	)

	r.handle(
		"PUT /vault/{vaultID}/record/{recordID}",
		handler.UpdateRecord,
	)

	r.handle(
		"DELETE /vault/{vaultID}/record/{recordID}",
		handler.DeleteRecord,
	)

	r.handle(
		"GET /vault/{vaultID}/record/blob",
		handler.RecordBlob,
	)

	// Record sync

	r.handle(
		"GET /vault/{vaultID}/record/changes/count",
		handler.PendingRecordCount,
	)

	r.handle(
		"GET /vault/{vaultID}/record/changes",
		handler.GetPendingRecordChanges,
	)

	r.handle(
		"POST /vault/{vaultID}/record/changes/synced",
		handler.MarkRecordChangesSynced,
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
		"POST /access-control/{id}/revoke",
		handler.Revoke,
	)

	r.handle(
		"DELETE /access-control/{id}",
		handler.DeletePermission,
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

	r.handle(
		"POST /access-control/vault-access",
		handler.GrantPrivilege,
	)
}

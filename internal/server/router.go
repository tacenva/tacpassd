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

	router.registerHealthRoutes()
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

func (r *Router) registerHealthRoutes() {
	r.mux.HandleFunc("GET /health", func(
		w http.ResponseWriter,
		req *http.Request,
	) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func (r *Router) registerAuthRoutes(
	handler *auth.Handler,
) {
	r.mux.HandleFunc( // dont use middleware
		"POST /auth/enroll",
		handler.Enroll,
	)

	r.handle(
		"GET /auth/",
		handler.Data,
	)
}

func (r *Router) registerVaultRoutes(
	handler *vault.Handler,
) {
	// Vault
	// r.handle(
	// 	"GET /vault",
	// 	handler.ListVault,
	// )

	// r.handle(
	// 	"GET /vault/changes/count",
	// 	handler.VaultChangeCount,
	// )

	// r.handle(
	// 	"GET /vault/changes",
	// 	handler.GetVaultChangesAfter,
	// )

	// r.handle(
	// 	"POST /vault/sync",
	// 	handler.SyncVault,
	// )

	// Record
	r.handle(
		"GET /vault/{vaultID}/record/blob",
		handler.GetRecordBlob,
	)

	r.handle(
		"POST /vault/{vaultID}/record/blob",
		handler.StoreRecordBlob,
	)

	r.handle(
		"GET /vault/{vaultID}/record/changes/count",
		handler.RecordChangeCount,
	)

	r.handle(
		"GET /vault/{vaultID}/record/changes",
		handler.GetRecordChangesAfter,
	)

	r.handle(
		"POST /vault/{vaultID}/record/sync",
		handler.SyncRecord,
	)
}

func (r *Router) registerAccessControlRoutes(
	handler *accesscontrol.Handler,
) {
	// Access Group
	r.handle(
		"POST /access-control/groups",
		handler.CreateGroup,
	)

	r.handle(
		"PUT /access-control/groups/{id}",
		handler.UpdateGroup,
	)

	r.handle(
		"DELETE /access-control/groups/{id}",
		handler.DeleteGroup,
	)

	r.handle(
		"GET /access-control/groups/tree",
		handler.GroupWithChildren,
	)

	r.handle(
		"GET /access-control/groups/{id}/tree",
		handler.GroupWithChildren,
	)

	// Access Unit
	r.handle(
		"POST /access-control/groups/{id}/units",
		handler.CreateUnit,
	)

	r.handle(
		"GET /access-control/groups/{id}/units",
		handler.UnitList,
	)

	r.handle(
		"PUT /access-control/units/{id}",
		handler.UpdateUnit,
	)

	r.handle(
		"DELETE /access-control/units/{id}",
		handler.DeleteUnit,
	)

	r.handle(
		"PATCH /access-control/units/{id}/revoke",
		handler.SetRevokeUnit,
	)

	// // Public Keys
	// r.handle(
	// 	"POST /access-control/groups/public-keys",
	// 	handler.GetPublicKeys,
	// )

	// User
	r.handle(
		"PATCH /access-control/users/{id}/approve",
		handler.SetApprovalUser,
	)

	r.handle(
		"DELETE /access-control/users/{id}",
		handler.DeleteUser,
	)
}

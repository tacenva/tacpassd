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

	r.mux.HandleFunc( // dont use middleware
		"GET /auth/status",
		handler.CheckStatus,
	)

	r.handle(
		"GET /auth/group",
		handler.GroupData,
	)
}

func (r *Router) registerVaultRoutes(
	handler *vault.Handler,
) {
	// Vault
	r.handle(
		"QUERY /vault/public-keys",
		handler.GetPublicKeys,
	)

	r.handle(
		"GET /vault",
		handler.ListVault,
	)

	r.handle(
		"GET /vault/changes/count",
		handler.VaultChangeCount,
	)

	r.handle(
		"GET /vault/changes",
		handler.GetVaultChangesAfter,
	)

	r.handle(
		"POST /vault/sync",
		handler.SyncVault,
	)

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
	r.handle(
		"GET /access-control",
		handler.List,
	)

	r.handle(
		"POST /access-control",
		handler.Create,
	)

	r.handle(
		"PUT /access-control/{id}",
		handler.Update,
	)

	r.handle(
		"DELETE /access-control/{id}",
		handler.DeletePermission,
	)

	r.handle(
		"PATCH /access-control/{id}/revoke",
		handler.SetRevoked,
	)

	// User
	r.handle(
		"GET /access-control/{id}/users",
		handler.UserList,
	)

	r.handle(
		"PATCH /access-control/users/{userId}/approval",
		handler.SetUserStatus,
	)

	// Permission groups
	r.handle(
		"GET /access-control/groups",
		handler.GroupList,
	)

	r.handle(
		"PUT /access-control/groups/{id}",
		handler.UpdateGroup,
	)

	r.handle(
		"DELETE /access-control/groups/{id}",
		handler.DeleteGroup,
	)
}

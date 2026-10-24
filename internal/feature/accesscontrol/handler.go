package accesscontrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	coreAC "github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/config"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	accesscontrolService *coreAC.Service
	sotID                string
}

func NewHandler(
	accesscontrolService *coreAC.Service,
	cfg *config.Config,
) *Handler {
	return &Handler{
		accesscontrolService: accesscontrolService,
		sotID:                cfg.SotID,
	}
}

func (h *Handler) List(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	permissions, err := h.accesscontrolService.List(
		authUser,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		permissions,
	)
}

func (h *Handler) Create(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var request entity.Permission
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	request.Group.Name = strings.TrimSpace(request.Group.Name)

	permission, keyPair, err := h.accesscontrolService.Create(
		authUser,
		request.Name,
		request.Privilege,
		&request.Group,
		request.AutoApprove,
		h.sotID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := struct {
		Permission *entity.Permission `json:"permission"`
		KeyPair    *keyring.KeyPair   `json:"keypair"`
	}{
		Permission: permission,
		KeyPair:    keyPair,
	}

	writeJSON(w, http.StatusCreated, response)
}

func (h *Handler) Update(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "access control id is required", http.StatusBadRequest)
		return
	}

	var request entity.Permission
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	request.ID = id
	request.Name = strings.TrimSpace(request.Name)
	request.Group.Name = strings.TrimSpace(request.Group.Name)

	if request.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.Update(authUser, &request, h.sotID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) SetRevoked(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revoked *bool `json:"revoked"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Revoked == nil {
		http.Error(w, "Field revoked is required", http.StatusBadRequest)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "Permission ID is required", http.StatusBadRequest)
		return
	}

	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.accesscontrolService.SetRevoked(authUser, id, h.sotID, *req.Revoked); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"revoked": *req.Revoked,
	})
}

func (h *Handler) UserList(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	permissionID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if permissionID == "" {
		http.Error(
			w,
			"permission id is required",
			http.StatusBadRequest,
		)
		return
	}

	users, err := h.accesscontrolService.UserList(
		authUser,
		permissionID,
		h.sotID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		users,
	)
}

func (h *Handler) SetUserStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req struct {
		Status entity.UserStatus `json:"status"`
	}

	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	userID := strings.TrimSpace(
		r.PathValue("userId"),
	)

	if userID == "" {
		http.Error(
			w,
			"user id is required",
			http.StatusBadRequest,
		)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.accesscontrolService.SetUserStatus(
		authUser,
		h.sotID,
		userID,
		req.Status,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
}

func (h *Handler) handleServiceError(
	w http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(err, coreAC.ErrPermission):
		http.Error(
			w,
			"forbidden",
			http.StatusForbidden,
		)

	case errors.Is(err, coreAC.ErrNotFound):
		http.Error(
			w,
			"not found",
			http.StatusNotFound,
		)

	default:
		http.Error(
			w,
			"internal server error",
			http.StatusInternalServerError,
		)
	}
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	data any,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) DeletePermission(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	permissionID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if permissionID == "" {
		http.Error(
			w,
			"id is required",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.accesscontrolService.DeletePermission(
		authUser,
		permissionID,
		h.sotID,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GroupList(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !authUser.HasAdminPermission() {
		h.handleServiceError(w, coreAC.ErrPermission)
		return
	}

	groups, err := h.accesscontrolService.GroupList(
		h.sotID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, groups)
}

func (h *Handler) UpdateGroup(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		http.Error(w, "group id is required", http.StatusBadRequest)
		return
	}

	var request entity.PermissionGroup
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	request.ID = groupID
	request.Name = strings.TrimSpace(request.Name)

	if request.Name == "" {
		http.Error(w, "group name is required", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.UpdateGroup(authUser, &request, h.sotID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteGroup(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		http.Error(w, "group id is required", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.DeleteGroup(authUser, groupID, h.sotID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

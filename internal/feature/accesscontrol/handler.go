package accesscontrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	coreAC "github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	accesscontrolService *coreAC.Service
}

func NewHandler(
	accesscontrolService *coreAC.Service,
) *Handler {
	return &Handler{
		accesscontrolService: accesscontrolService,
	}
}

type createRequest struct {
	Name      string           `json:"name"`
	Privilege entity.Privilege `json:"privilege"`
}

type changeNameRequest struct {
	Name string `json:"name"`
}

type changePrivilegeRequest struct {
	Privilege entity.Privilege `json:"privilege"`
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

func (h *Handler) Get(
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

	permission, err := h.accesscontrolService.Get(
		authUser,
		permissionID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		permission,
	)
}

func (h *Handler) Create(
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

	var request createRequest

	if err := json.NewDecoder(r.Body).Decode(
		&request,
	); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	request.Name = strings.TrimSpace(request.Name)

	if request.Name == "" {
		http.Error(
			w,
			"name is required",
			http.StatusBadRequest,
		)
		return
	}

	permission, keypair, err := h.accesscontrolService.Create(
		authUser,
		request.Name,
		request.Privilege,
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
		KeyPair:    keypair,
	}

	writeJSON(
		w,
		http.StatusCreated,
		response,
	)
}

func (h *Handler) ChangeName(
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

	id := strings.TrimSpace(
		r.PathValue("id"),
	)

	if id == "" {
		http.Error(
			w,
			"access control id is required",
			http.StatusBadRequest,
		)
		return
	}

	var request changeNameRequest

	if err := json.NewDecoder(r.Body).Decode(
		&request,
	); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	request.Name = strings.TrimSpace(request.Name)

	if request.Name == "" {
		http.Error(
			w,
			"name is required",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.accesscontrolService.ChangeName(
		authUser,
		id,
		request.Name,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ChangePrivilege(
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

	var request changePrivilegeRequest

	if err := json.NewDecoder(r.Body).Decode(
		&request,
	); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.accesscontrolService.ChangePrivilege(
		authUser,
		permissionID,
		request.Privilege,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Revoke(
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

	if err := h.accesscontrolService.Revoke(
		authUser,
		permissionID,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

func (h *Handler) ApproveUser(
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

	user, err := h.accesscontrolService.ApproveUser(
		authUser,
		userID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		user,
	)
}

func (h *Handler) RevokeUser(
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

	user, err := h.accesscontrolService.RevokeUser(
		authUser,
		userID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		user,
	)
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

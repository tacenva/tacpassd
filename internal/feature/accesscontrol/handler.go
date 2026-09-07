package accesscontrol

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

type Handler struct {
	accesscontrolService *accesscontrol.Service
}

func NewHandler(
	accesscontrolService *accesscontrol.Service,
) *Handler {
	return &Handler{
		accesscontrolService: accesscontrolService,
	}
}

type changePrivilegeRequest struct {
	Privilege entity.Privilege `json:"privilege"`
}

func (h *Handler) List(
	w http.ResponseWriter,
	r *http.Request,
) {
	permissions, err := h.accesscontrolService.List()
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		permissions,
	)
}

func (h *Handler) GetByPublicKey(
	w http.ResponseWriter,
	r *http.Request,
) {
	publicKey := strings.TrimSpace(
		r.PathValue("publicKey"),
	)

	if publicKey == "" {
		http.Error(
			w,
			"public key is required",
			http.StatusBadRequest,
		)
		return
	}

	permission, err := h.accesscontrolService.GetByPublicKey(
		publicKey,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
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
	var request struct {
		Privilege entity.Privilege `json:"privilege"`
	}

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

	permission, keypair, err := h.accesscontrolService.Create(
		request.Privilege,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
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

func (h *Handler) ChangePrivilege(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := strings.TrimSpace(
		r.PathValue("id"),
	)

	if id == "" {
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
		id,
		request.Privilege,
	); err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Revoke(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := strings.TrimSpace(
		r.PathValue("id"),
	)

	if id == "" {
		http.Error(
			w,
			"id is required",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.accesscontrolService.Revoke(
		id,
	); err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UserList(
	w http.ResponseWriter,
	r *http.Request,
) {
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
		permissionID,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
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
		userID,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
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
		userID,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		user,
	)
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

	if err := json.NewEncoder(w).Encode(data); err != nil {
		return
	}
}

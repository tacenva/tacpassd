package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
)

type Handler struct {
	authService *auth.Service
}

func NewHandler(
	authService *auth.Service,
) *Handler {
	return &Handler{
		authService: authService,
	}
}

func (h *Handler) Enroll(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	defer r.Body.Close()

	var request contract.EnrollRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	request.Hostname = strings.TrimSpace(
		request.Hostname,
	)

	request.PublicKey = strings.TrimSpace(
		request.PublicKey,
	)

	if request.Hostname == "" {
		http.Error(
			w,
			"hostname is required",
			http.StatusBadRequest,
		)
		return
	}

	if request.PublicKey == "" {
		http.Error(
			w,
			"public key is required",
			http.StatusBadRequest,
		)
		return
	}

	response, err := h.authService.Enroll(
		&contract.EnrollRequest{
			Hostname:  request.Hostname,
			PublicKey: request.PublicKey,
		},
		entity.UserStatusPending,
	)
	if err != nil {
		http.Error(
			w,
			"failed to request enrollment",
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusAccepted)

	_ = json.NewEncoder(w).Encode(response)
}

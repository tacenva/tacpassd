package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tacenva/tacenva-core/auth"
	"github.com/tacenva/tacenva-core/config"
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	authService *auth.Service
	sotID       string
}

func NewHandler(
	authService *auth.Service,
	cfg *config.Config,
) *Handler {
	return &Handler{
		authService: authService,
		sotID:       cfg.SotID,
	}
}

func (h *Handler) Enroll(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()

	var request tacenvacontract.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	request.Hostname = strings.TrimSpace(request.Hostname)
	request.PublicKey = strings.TrimSpace(request.PublicKey)

	if request.Hostname == "" {
		http.Error(w, "hostname is required", http.StatusBadRequest)
		return
	}

	if request.PublicKey == "" {
		http.Error(w, "public key is required", http.StatusBadRequest)
		return
	}

	response, err := h.authService.Enroll(
		&request,
		h.sotID,
		tacenvaentity.UserStatusPending,
	)
	if err != nil {
		http.Error(
			w,
			"failed to request enrollment",
			http.StatusInternalServerError,
		)
		return
	}

	writeJSON(w, http.StatusAccepted, response)
}

// func (h *Handler) CheckStatus(
// 	w http.ResponseWriter,
// 	r *http.Request,
// ) {
// 	if r.Method != http.MethodGet {
// 		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	token := bearerToken(r)
// 	if token == "" {
// 		http.Error(
// 			w,
// 			"authorization token is required",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	response, err := h.authService.CheckStatus(token, h.sotID)
// 	if err != nil {
// 		http.Error(
// 			w,
// 			"failed to check status",
// 			http.StatusInternalServerError,
// 		)
// 		return
// 	}

// 	writeJSON(w, http.StatusOK, response)
// }

func (h *Handler) GroupData(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
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

	groupData, err := h.authService.GetAuthDataWithGroupList(authUser.Token, h.sotID)
	if err != nil {
		http.Error(
			w,
			"failed to get group data",
			http.StatusInternalServerError,
		)
		return
	}

	writeJSON(w, http.StatusOK, groupData)
}

// func bearerToken(r *http.Request) string {
// 	const prefix = "Bearer "

// 	header := r.Header.Get("Authorization")
// 	if !strings.HasPrefix(header, prefix) {
// 		return ""
// 	}

// 	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
// }

func writeJSON(
	w http.ResponseWriter,
	statusCode int,
	data any,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

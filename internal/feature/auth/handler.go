package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
)

type Handler struct {
	authService *auth.Service
}

type EnrollRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}

type EnrollResponse struct {
	Status    string `json:"status"`
	AuthToken string `json:"auth_token"`
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

	var request EnrollRequest

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

	authToken, err := h.authService.Enroll(
		request.Hostname,
		request.PublicKey,
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

	response := EnrollResponse{
		Status:    "pending",
		AuthToken: authToken,
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusAccepted)

	_ = json.NewEncoder(w).Encode(response)
}

// func (h *Handler) GetStatus(
// 	w http.ResponseWriter,
// 	r *http.Request,
// ) {
// 	if r.Method != http.MethodGet {
// 		http.Error(
// 			w,
// 			"method not allowed",
// 			http.StatusMethodNotAllowed,
// 		)
// 		return
// 	}

// 	authHeader := r.Header.Get("Authorization")

// 	if authHeader == "" {
// 		http.Error(
// 			w,
// 			"authorization header is required",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	const bearerPrefix = "Bearer "

// 	if !strings.HasPrefix(
// 		authHeader,
// 		bearerPrefix,
// 	) {
// 		http.Error(
// 			w,
// 			"invalid authorization header",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	token := strings.TrimSpace(
// 		strings.TrimPrefix(
// 			authHeader,
// 			bearerPrefix,
// 		),
// 	)

// 	if token == "" {
// 		http.Error(
// 			w,
// 			"bearer token is required",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	err := h.authService.GetStatus(
// 		token,
// 	)
// 	if err != nil {
// 		http.Error(
// 			w,
// 			"failed to get authentication status",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }

package vault

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/tacenva/tacpass-core/config"
	"github.com/tacenva/tacpass-core/contract"
	VaultServiceCore "github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	vaultServiceCore   *VaultServiceCore.Service
	vaultRecordService *vaultrecord.Service
	vaultDir           string
	sotID              string
}

func NewHandler(
	vaultServiceCore *VaultServiceCore.Service,
	cfg *config.Config,
) *Handler {
	return &Handler{
		vaultServiceCore:   vaultServiceCore,
		vaultRecordService: vaultServiceCore.GetVaultRecordService(),
		vaultDir:           cfg.VaultDir(),
		sotID:              cfg.SoTULID,
	}
}

func (h *Handler) ConnectedPublicKeys(
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

	permissionList, err := h.vaultServiceCore.ConnectedPublicKeys(
		authUser,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(
		permissionList,
	)
}

func (h *Handler) SyncVault(
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

	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	var pendingChange contract.PendingVaultChange

	if err := json.NewDecoder(r.Body).Decode(&pendingChange); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.vaultServiceCore.SyncOnSoT(
		h.sotID,
		&pendingChange,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetVaultSyncLatestChangeID(
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

	lastChangeID, err := h.vaultServiceCore.GetSyncLatestChangeId(
		h.sotID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(
		struct {
			LastChangeID string `json:"last_change_id"`
		}{
			LastChangeID: lastChangeID,
		},
	)
}

func (h *Handler) VaultChangeCount(
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

	startChangeID := strings.TrimSpace(
		r.URL.Query().Get("start_change_id"),
	)

	count, err := h.vaultServiceCore.GetChangeCount(
		h.sotID,
		startChangeID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(
		contract.PendingTotalChanges{
			Count: count,
		},
	)
}

func (h *Handler) GetVaultChangesAfter(
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

	startChangeID := strings.TrimSpace(
		r.URL.Query().Get("start_change_id"),
	)

	limitValue := strings.TrimSpace(
		r.URL.Query().Get("limit"),
	)
	if limitValue == "" {
		http.Error(
			w,
			"limit is required",
			http.StatusBadRequest,
		)
		return
	}

	limit, err := strconv.Atoi(limitValue)
	if err != nil || limit <= 0 {
		http.Error(
			w,
			"limit must be a positive integer",
			http.StatusBadRequest,
		)
		return
	}

	changes, err := h.vaultServiceCore.GetChangesAfterOnSoT(
		authUser,
		h.sotID,
		startChangeID,
		limit,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	changesJSON, _ := json.MarshalIndent(changes, "", "  ")
	log.Printf("[DEBUG] changes:\n%s", string(changesJSON))

	_ = json.NewEncoder(w).Encode(changes)
}

func (h *Handler) ListVault(
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

	vaultAccessList, err := h.vaultServiceCore.VaultAccessList(
		authUser,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(vaultAccessList)
}

func (h *Handler) GetRecordSyncLatestChangeID(
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

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	lastChangeID, err := h.vaultRecordService.GetSyncLatestChangeId(
		h.sotID,
		vaultID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(
		struct {
			LastChangeID string `json:"last_change_id"`
		}{
			LastChangeID: lastChangeID,
		},
	)
}

func (h *Handler) GetRecordBlob(
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

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	data, err := h.vaultRecordService.GetBlob(
		authUser,
		h.vaultDir,
		vaultID,
		h.sotID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/octet-stream",
	)

	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(data)
}

func (h *Handler) StoreRecordBlob(
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

	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(
			w,
			"failed to read request body",
			http.StatusBadRequest,
		)
		return
	}
	defer r.Body.Close()

	if len(data) == 0 {
		http.Error(
			w,
			"request body cannot be empty",
			http.StatusBadRequest,
		)
		return
	}

	err = h.vaultRecordService.StoreBlob(
		authUser,
		h.vaultDir,
		vaultID,
		h.sotID,
		data,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RecordChangeCount(
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

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	startChangeID := strings.TrimSpace(
		r.URL.Query().Get("start_change_id"),
	)

	count, err := h.vaultRecordService.GetChangeCount(
		// authUser,
		h.sotID,
		vaultID,
		startChangeID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(
		contract.PendingTotalChanges{
			Count: count,
		},
	)
}

func (h *Handler) GetRecordChangesAfter(
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

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	startChangeID := strings.TrimSpace(
		r.URL.Query().Get("start_change_id"),
	)

	limitValue := strings.TrimSpace(
		r.URL.Query().Get("limit"),
	)
	if limitValue == "" {
		http.Error(
			w,
			"limit is required",
			http.StatusBadRequest,
		)
		return
	}

	limit, err := strconv.Atoi(limitValue)
	if err != nil || limit <= 0 {
		http.Error(
			w,
			"limit must be a positive integer",
			http.StatusBadRequest,
		)
		return
	}

	changes, err := h.vaultRecordService.GetChangesAfter(
		h.vaultDir,
		vaultID,
		h.sotID,
		startChangeID,
		limit,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(changes)
}

func (h *Handler) SyncRecord(
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

	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(
			w,
			"unauthorized",
			http.StatusUnauthorized,
		)
		return
	}

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	var pendingChange contract.PendingVaultRecordChange

	if err := json.NewDecoder(r.Body).Decode(&pendingChange); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	if len(pendingChange.SyncChanges) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.vaultRecordService.Sync(
		h.vaultDir,
		h.sotID,
		vaultID,
		&pendingChange,
		nil,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleServiceError(
	w http.ResponseWriter,
	err error,
) {
	log.Printf("err: %s", err)
	switch {
	case errors.Is(err, VaultServiceCore.ErrPermission):
		http.Error(
			w,
			"forbidden",
			http.StatusForbidden,
		)

	case errors.Is(err, VaultServiceCore.ErrNotFound):
		http.Error(
			w,
			"vault not found",
			http.StatusNotFound,
		)

	case errors.Is(err, VaultServiceCore.ErrNameEmpty):
		http.Error(
			w,
			"vault name cannot be empty",
			http.StatusBadRequest,
		)

	default:
		http.Error(
			w,
			"internal server error",
			http.StatusInternalServerError,
		)
	}
}

func getVaultID(
	r *http.Request,
) (string, bool) {
	vaultID := strings.TrimSpace(
		r.PathValue("vaultID"),
	)

	if vaultID == "" {
		return "", false
	}

	return vaultID, true
}

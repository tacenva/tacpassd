package vault

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/tacenva/tacenva-core/config"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	vault              *vault.Service
	vaultRecordService *vaultrecord.Service
	vaultDir           string
	sotID              string
}

func NewHandler(
	vault *vault.Service,
	cfg *config.Config,
) *Handler {
	return &Handler{
		vault:              vault,
		vaultRecordService: vault.GetVaultRecordService(),
		vaultDir:           cfg.VaultDir(),
		sotID:              cfg.SotID,
	}
}

// func (h *Handler) GetPublicKeys(
// 	w http.ResponseWriter,
// 	r *http.Request,
// ) {
// 	if r.Method != "QUERY" {
// 		http.Error(
// 			w,
// 			"method not allowed",
// 			http.StatusMethodNotAllowed,
// 		)
// 		return
// 	}

// 	authUser := middleware.GetAuthUser(r)
// 	if authUser == nil {
// 		http.Error(
// 			w,
// 			"unauthorized",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	var req tacenvacontract.PermissionGroupReq

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(
// 			w,
// 			"invalid request body",
// 			http.StatusBadRequest,
// 		)
// 		return
// 	}

// 	groupIDs := make([]string, 0, len(req.GroupIDs))

// 	for _, id := range req.GroupIDs {
// 		id = strings.TrimSpace(id)
// 		if id != "" {
// 			groupIDs = append(groupIDs, id)
// 		}
// 	}

// 	if len(groupIDs) == 0 {
// 		http.Error(
// 			w,
// 			"group_ids is required",
// 			http.StatusBadRequest,
// 		)
// 		return
// 	}

// 	permissionList, err := h.vault.GetPublicKeysByGroupIDs(
// 		authUser,
// 		groupIDs,
// 		h.sotID,
// 	)
// 	if err != nil {
// 		h.handleServiceError(w, err)
// 		return
// 	}

// 	w.Header().Set(
// 		"Content-Type",
// 		"application/json",
// 	)

// 	w.WriteHeader(http.StatusOK)

// 	_ = json.NewEncoder(w).Encode(permissionList)
// }

func (h *Handler) ParseSyncQuery(
	w http.ResponseWriter,
	r *http.Request,
) (string, int, error) {
	startChangeID := strings.TrimSpace(
		r.URL.Query().Get("start_change_id"),
	)

	limitValue := strings.TrimSpace(
		r.URL.Query().Get("limit"),
	)
	if limitValue == "" {
		return "", 0, errors.New("limit is required")
	}

	limit, err := strconv.Atoi(limitValue)
	if err != nil || limit < 0 {
		return "", 0, errors.New("limit must be a positive integer")
	}

	return startChangeID, limit, nil
}

// func (h *Handler) SyncVault(
// 	w http.ResponseWriter,
// 	r *http.Request,
// ) {
// 	if r.Method != http.MethodPost {
// 		http.Error(
// 			w,
// 			"method not allowed",
// 			http.StatusMethodNotAllowed,
// 		)
// 		return
// 	}

// 	authUser := middleware.GetAuthUser(r)
// 	if authUser == nil {
// 		http.Error(
// 			w,
// 			"unauthorized",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	var pendingChange tacpasscontract.PendingVaultChange

// 	if err := json.NewDecoder(r.Body).Decode(&pendingChange); err != nil {
// 		http.Error(
// 			w,
// 			"invalid request body",
// 			http.StatusBadRequest,
// 		)
// 		return
// 	}

// 	startChangeID, limit, err := h.ParseSyncQuery(
// 		w,
// 		r,
// 	)
// 	if err != nil {
// 		http.Error(
// 			w,
// 			err.Error(),
// 			http.StatusBadRequest,
// 		)
// 	}

// 	successList, err := h.vault.SyncOnSot(
// 		h.sotID,
// 		authUser.PermissionID,
// 		authUser.Permission.GroupID,
// 		authUser.Hostname,
// 		startChangeID,
// 		limit,
// 		&pendingChange,
// 	)
// 	if err != nil {
// 		h.handleServiceError(w, err)
// 		return
// 	}

// 	w.WriteHeader(http.StatusNoContent)

// 	_ = json.NewEncoder(w).Encode(successList)
// }

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

	lastChangeID, err := h.vault.GetSyncLatestChangeID(
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

	pendingTotalChanges, err := h.vault.GetChangeCount(
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
		pendingTotalChanges,
	)
}

// func (h *Handler) GetVaultChangesAfter(
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

// 	authUser := middleware.GetAuthUser(r)
// 	if authUser == nil {
// 		http.Error(
// 			w,
// 			"unauthorized",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	startChangeID, limit, err := h.ParseSyncQuery(
// 		w,
// 		r,
// 	)
// 	if err != nil {
// 		http.Error(
// 			w,
// 			err.Error(),
// 			http.StatusBadRequest,
// 		)
// 	}

// 	changes, err := h.vault.GetChangesAfterOnSot(
// 		h.sotID,
// 		authUser.PermissionID,
// 		startChangeID,
// 		limit,
// 	)
// 	if err != nil {
// 		h.handleServiceError(w, err)
// 		return
// 	}

// 	w.Header().Set(
// 		"Content-Type",
// 		"application/json",
// 	)

// 	w.WriteHeader(http.StatusOK)

// 	_ = json.NewEncoder(w).Encode(changes)
// }

// func (h *Handler) ListVault(
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

// 	authUser := middleware.GetAuthUser(r)
// 	if authUser == nil {
// 		http.Error(
// 			w,
// 			"unauthorized",
// 			http.StatusUnauthorized,
// 		)
// 		return
// 	}

// 	vaultAccessList, err := h.vault.VaultList(
// 		authUser,
// 	)
// 	if err != nil {
// 		h.handleServiceError(w, err)
// 		return
// 	}

// 	w.Header().Set(
// 		"Content-Type",
// 		"application/json",
// 	)

// 	w.WriteHeader(http.StatusOK)

// 	_ = json.NewEncoder(w).Encode(vaultAccessList)
// }

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

	data, err := h.vaultRecordService.Remote.GetBlob(
		authUser,
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

	err = h.vaultRecordService.Remote.StoreBlob(
		authUser,
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

	startChangeID, limit, err := h.ParseSyncQuery(
		w,
		r,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusBadRequest,
		)
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

	startChangeID, limit, err := h.ParseSyncQuery(
		w,
		r,
	)
	if err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusBadRequest,
		)
	}

	err = h.vaultRecordService.SyncOnSot(
		authUser,
		h.vaultDir,
		h.sotID,
		vaultID,
		startChangeID,
		limit,
		&pendingChange,
	)
	if err != nil {
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
	case errors.Is(err, vault.ErrPermission):
		http.Error(
			w,
			"forbidden",
			http.StatusForbidden,
		)

	case errors.Is(err, vault.ErrNotFound):
		http.Error(
			w,
			"vault not found",
			http.StatusNotFound,
		)

	case errors.Is(err, vault.ErrNameEmpty):
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

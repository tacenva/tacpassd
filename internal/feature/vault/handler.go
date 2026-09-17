package vault

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/tacenva/database"
	VaultServiceCore "github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultrecord"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	vaultServiceCore   *VaultServiceCore.Service
	vaultRecordService *vaultrecord.RawService
}

func NewHandler(
	vaultServiceCore *VaultServiceCore.Service,
	tacenvaDB *database.DB,
) *Handler {
	return &Handler{
		vaultServiceCore:   vaultServiceCore,
		vaultRecordService: vaultServiceCore.VaultRecordService,
	}
}

func (h *Handler) CreateVault(
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

	var request struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
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
			"vault name is required",
			http.StatusBadRequest,
		)
		return
	}

	vaultAccess, err := h.vaultServiceCore.Create(
		authUser,
		request.Name,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusCreated)

	_ = json.NewEncoder(w).Encode(vaultAccess)
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

func (h *Handler) UpdateVault(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPut {
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

	var request struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
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
			"vault name is required",
			http.StatusBadRequest,
		)
		return
	}

	vault, err := h.vaultServiceCore.Update(
		authUser,
		vaultID,
		request.Name,
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

	_ = json.NewEncoder(w).Encode(vault)
}

func (h *Handler) DeleteVault(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodDelete {
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

	if err := h.vaultServiceCore.Delete(
		authUser,
		vaultID,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) CreateRecord(
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

	if len(data) == 0 {
		http.Error(
			w,
			"request body cannot be empty",
			http.StatusBadRequest,
		)
		return
	}

	recordID, err := h.vaultRecordService.Create(
		vaultID,
		data,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(
		"Content-Type",
		"text/plain",
	)

	w.WriteHeader(http.StatusCreated)

	_, _ = w.Write(
		[]byte(recordID),
	)
}

func (h *Handler) UpdateRecord(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPut {
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

	recordID, ok := getRecordID(r)
	if !ok {
		http.Error(
			w,
			"record id is required",
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

	if len(data) == 0 {
		http.Error(
			w,
			"request body cannot be empty",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.vaultRecordService.Update(
		vaultID,
		recordID,
		data,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteRecord(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodDelete {
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

	recordID, ok := getRecordID(r)
	if !ok {
		http.Error(
			w,
			"record id is required",
			http.StatusBadRequest,
		)
		return
	}

	if err := h.vaultRecordService.Delete(
		vaultID,
		recordID,
	); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RecordBlob(
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

	data, err := h.vaultRecordService.Blob(
		vaultID,
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

func (h *Handler) PendingRecordCount(
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

	count, err := h.vaultRecordService.PendingCount(
		authUser.ID,
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
			Count int64 `json:"count"`
		}{
			Count: count,
		},
	)
}

func (h *Handler) GetPendingRecordChanges(
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

	changes, err := h.vaultRecordService.GetPendingChanges(
		authUser.ID,
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

	_ = json.NewEncoder(w).Encode(changes)
}

func (h *Handler) PendingVaultCount(
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

	count, err := h.vaultServiceCore.PendingCount(
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
		struct {
			Count int64 `json:"count"`
		}{
			Count: count,
		},
	)
}

func (h *Handler) GetPendingVaultChanges(
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

	changes, err := h.vaultServiceCore.GetPendingChanges(
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

	_ = json.NewEncoder(w).Encode(changes)
}

func (h *Handler) CheckVaultAccessible(
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

	vaultID, ok := getVaultID(r)
	if !ok {
		http.Error(
			w,
			"vault id is required",
			http.StatusBadRequest,
		)
		return
	}

	permissionID := strings.TrimSpace(
		r.URL.Query().Get("permissionID"),
	)

	if permissionID == "" {
		http.Error(
			w,
			"permission id is required",
			http.StatusBadRequest,
		)
		return
	}

	accessible, err := h.vaultServiceCore.IsVaultAccesible(
		vaultID,
		permissionID,
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
			Accessible bool `json:"accessible"`
		}{
			Accessible: accessible,
		},
	)
}

func (h *Handler) handleServiceError(
	w http.ResponseWriter,
	err error,
) {
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

func getRecordID(
	r *http.Request,
) (string, bool) {
	recordID := strings.TrimSpace(
		r.PathValue("recordID"),
	)

	if recordID == "" {
		return "", false
	}

	return recordID, true
}

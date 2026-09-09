package vault

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	VaultServiceCore "github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultaccess"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	vaultServiceCore *VaultServiceCore.Service
	vaultService     *Service
}

func NewHandler(
	vaultServiceCore *VaultServiceCore.Service,
	tacenvaDB *database.DB,
	vaultaccessService *vaultaccess.Service,
) *Handler {
	return &Handler{
		vaultServiceCore: vaultServiceCore,
		vaultService: NewService(
			tacenvaDB,
			vaultaccessService,
			vaultServiceCore,
		),
	}
}

// func (h *Handler) VaultAccessList(
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

// 	vaultList, err := h.vaultServiceCore.VaultAccessList(
// 		authUser,
// 	)
// 	if err != nil {
// 		http.Error(
// 			w,
// 			"failed to get vault list",
// 			http.StatusInternalServerError,
// 		)
// 		return
// 	}

// 	w.Header().Set(
// 		"Content-Type",
// 		"application/json",
// 	)

// 	w.WriteHeader(http.StatusOK)

// 	_ = json.NewEncoder(w).Encode(
// 		vaultList,
// 	)
// }

func (h *Handler) CheckVaultSync(
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
		ReplicaVaultHash string `json:"replica_vault_hash"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	request.ReplicaVaultHash = strings.TrimSpace(
		request.ReplicaVaultHash,
	)

	needSync, err := h.vaultService.CheckVaultSync(
		authUser,
		request.ReplicaVaultHash,
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
			NeedSync bool `json:"need_sync"`
		}{
			NeedSync: needSync,
		},
	)
}

func (h *Handler) VaultSync(
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
		ReplicaVaultHash string `json:"replica_vault_hash"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(
			w,
			"invalid request body",
			http.StatusBadRequest,
		)
		return
	}

	request.ReplicaVaultHash = strings.TrimSpace(
		request.ReplicaVaultHash,
	)

	vaultAccessList, needSync, serverVaultHash, err :=
		h.vaultService.VaultSync(
			authUser,
			request.ReplicaVaultHash,
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
			NeedSync        bool                 `json:"need_sync"`
			ServerVaultHash string               `json:"server_vault_hash"`
			VaultAccessList []entity.VaultAccess `json:"vault_access_list,omitempty"`
		}{
			NeedSync:        needSync,
			ServerVaultHash: serverVaultHash,
			VaultAccessList: vaultAccessList,
		},
	)
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

	recordID, err := h.vaultService.CreateRecord(
		authUser,
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

func (h *Handler) GetRecord(
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

	recordID, ok := getRecordID(r)
	if !ok {
		http.Error(
			w,
			"record id is required",
			http.StatusBadRequest,
		)
		return
	}

	data, err := h.vaultService.GetRecord(
		authUser,
		vaultID,
		recordID,
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

func (h *Handler) GetAllRecord(
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

	records, err := h.vaultService.GetAllRecord(
		authUser,
		vaultID,
	)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// []byte akan otomatis di-encode sebagai base64 oleh encoding/json.
	// Ini hanya transport encoding, bukan encryption.
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(
		records,
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

	if err := h.vaultService.UpdateRecord(
		authUser,
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

	if err := h.vaultService.DeleteRecord(
		authUser,
		vaultID,
		recordID,
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

	case errors.Is(err, ErrForbidden):
		http.Error(
			w,
			"forbidden",
			http.StatusForbidden,
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

package accesscontrol

import (
	"encoding/json"
	"net/http"

	"github.com/tacenva/tacenva-core/accesscontrol"
	"github.com/tacenva/tacenva-core/config"
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacpassd/internal/middleware"
)

type Handler struct {
	accesscontrolService *accesscontrol.Service
}

func NewHandler(
	accesscontrolService *accesscontrol.Service,
	_ *config.Config,
) *Handler {
	return &Handler{
		accesscontrolService: accesscontrolService,
	}
}

func requireMethod(
	w http.ResponseWriter,
	r *http.Request,
	method string,
) bool {
	if r.Method == method {
		return true
	}

	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// func getauthorizedUser(
// 	w http.ResponseWriter,
// 	r *http.Request,
// ) interface{} {
// 	// Gunakan helper ini hanya jika tipe return middleware.GetauthorizedUser
// 	// cocok dengan interface{} dan dapat di-cast ke tipe yang diperlukan.
// 	return nil
// }

func (h *Handler) CreateGroup(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req tacenvacontract.AccessGroupSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.CreateGroup(authorizedUser, &req); err != nil {
		http.Error(w, "failed to create access group", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) UpdateGroup(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		http.Error(w, "missing group ID", http.StatusBadRequest)
		return
	}

	var req tacenvaentity.AccessGroup
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.ID = groupID

	if err := h.accesscontrolService.UpdateGroup(authorizedUser, &req); err != nil {
		http.Error(w, "failed to update access group", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteGroup(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodDelete) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		http.Error(w, "missing group ID", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.DeleteGroup(authorizedUser, groupID); err != nil {
		http.Error(w, "failed to delete access group", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GroupWithChildren(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	groupID := r.PathValue("id")

	accessGroupTree, err := h.accesscontrolService.GroupWithChildren(
		authorizedUser,
		groupID,
	)
	if err != nil {
		http.Error(w, "failed to get access group tree", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(accessGroupTree); err != nil {
		return
	}
}

func (h *Handler) CreateUnit(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req tacenvacontract.AccessUnitSetupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.CreateUnit(
		authorizedUser,
		&req,
	); err != nil {
		http.Error(w, "failed to create access unit", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) UpdateUnit(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	unitID := r.PathValue("id")
	if unitID == "" {
		http.Error(w, "missing unit ID", http.StatusBadRequest)
		return
	}

	var req tacenvaentity.AccessUnit
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.ID = unitID

	if err := h.accesscontrolService.UpdateUnit(
		authorizedUser,
		&req,
	); err != nil {
		http.Error(w, "failed to update access unit", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteUnit(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodDelete) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	unitID := r.PathValue("id")
	if unitID == "" {
		http.Error(w, "missing unit ID", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.DeleteUnit(
		authorizedUser,
		unitID,
	); err != nil {
		http.Error(w, "failed to delete access unit", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) SetRevokeUnit(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodPatch) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	unitID := r.PathValue("id")
	if unitID == "" {
		http.Error(w, "missing unit ID", http.StatusBadRequest)
		return
	}

	var req tacenvacontract.RevokeStatusReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.SetRevokeUnit(
		authorizedUser,
		unitID,
		req.IsRevoked,
	); err != nil {
		http.Error(w, "failed to update access unit revoke status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UnitList(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		http.Error(w, "missing group ID", http.StatusBadRequest)
		return
	}

	unitList, err := h.accesscontrolService.UnitList(
		authorizedUser,
		groupID,
	)
	if err != nil {
		http.Error(w, "failed to list access units", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(unitList); err != nil {
		return
	}
}

func (h *Handler) SetApprovalUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodPatch) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		http.Error(w, "missing user ID", http.StatusBadRequest)
		return
	}

	var req tacenvacontract.RevokeStatusReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.SetApprovalUser(authorizedUser, userID, req.IsRevoked); err != nil {
		http.Error(w, "failed to approve user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !requireMethod(w, r, http.MethodDelete) {
		return
	}

	authorizedUser := middleware.GetauthorizedUser(r)
	if authorizedUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		http.Error(w, "missing user ID", http.StatusBadRequest)
		return
	}

	if err := h.accesscontrolService.DeleteUser(authorizedUser, userID); err != nil {
		http.Error(w, "failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// func (h *Handler) GetPublicKeys(
// 	w http.ResponseWriter,
// 	r *http.Request,
// ) {
// 	if !requireMethod(w, r, http.MethodPost) {
// 		return
// 	}

// 	authorizedUser := middleware.GetauthorizedUser(r)
// 	if authorizedUser == nil {
// 		http.Error(w, "unauthorized", http.StatusUnauthorized)
// 		return
// 	}

// 	var req tacenvacontract.PublicKeyOfGroupsReq
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "invalid request body", http.StatusBadRequest)
// 		return
// 	}

// 	groupIDs := make([]string, 0, len(req.GroupIDs))
// 	seen := make(map[string]struct{}, len(req.GroupIDs))

// 	for _, id := range req.GroupIDs {
// 		id = strings.TrimSpace(id)
// 		if id == "" {
// 			continue
// 		}
// 		if _, exists := seen[id]; exists {
// 			continue
// 		}

// 		seen[id] = struct{}{}
// 		groupIDs = append(groupIDs, id)
// 	}

// 	if len(groupIDs) == 0 {
// 		http.Error(w, "group_ids is required", http.StatusBadRequest)
// 		return
// 	}

// 	publicKeyOfGroups, err := h.accesscontrolService.PublicKeyOfGroups(
// 		authorizedUser,
// 		groupIDs,
// 	)
// 	if err != nil {
// 		http.Error(w, "failed to get public keys", http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	if err := json.NewEncoder(w).Encode(publicKeyOfGroups); err != nil {
// 		return
// 	}
// }

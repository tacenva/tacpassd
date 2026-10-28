package accesscontrol

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tacenva/tacenva-core/accesscontrol"
	"github.com/tacenva/tacenva-core/config"
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
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

func (h *Handler) GetPublicKeys(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authUser := middleware.GetAuthUser(r)
	if authUser == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req tacenvacontract.PublicKeyOfGroupsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	groupIDs := make([]string, 0, len(req.GroupIDs))
	seen := make(map[string]struct{}, len(req.GroupIDs))

	for _, id := range req.GroupIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}

		seen[id] = struct{}{}
		groupIDs = append(groupIDs, id)
	}

	if len(groupIDs) == 0 {
		http.Error(w, "group_ids is required", http.StatusBadRequest)
		return
	}

	permissionList, err := h.accesscontrolService.PublicKeyOfGroups(
		authUser,
		groupIDs,
	)
	if err != nil {
		http.Error(w, "failed to get public keys", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(permissionList)
}

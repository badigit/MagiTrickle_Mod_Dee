package v1

import (
	"net/http"
	"strings"
	"time"

	"magitrickle/api/utils"
	"magitrickle/api/v1/types"
	"magitrickle/models"
	"magitrickle/utils/intID"
	subscriptionutils "magitrickle/utils/subscriptions"

	"github.com/rs/zerolog/log"
)

func (h *Handler) GetSubscriptions(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, http.StatusOK, RespFromSubscriptions(h.app.Subscriptions()))
}

func (h *Handler) PutSubscriptions(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.SubscriptionsReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Subscriptions == nil {
		utils.WriteError(w, http.StatusBadRequest, "no subscriptions in request")
		return
	}

	existingByID := make(map[intID.ID]*models.Subscription)
	for _, subscription := range h.app.Subscriptions() {
		existingByID[subscription.ID] = subscription
	}

	newSubscriptions := make([]*models.Subscription, len(*req.Subscriptions))
	for i, subscriptionReq := range *req.Subscriptions {
		var existing *models.Subscription
		if subscriptionReq.ID != nil {
			existing = existingByID[*subscriptionReq.ID]
		}
		newSubscriptions[i], err = SubscriptionFromReq(subscriptionReq, existing)
		if err != nil {
			utils.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	h.app.ClearSubscriptions()
	for _, subscription := range newSubscriptions {
		if err := h.app.AddSubscription(subscription); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := h.app.RebuildSubscriptionGroups(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJson(w, http.StatusOK, RespFromSubscriptions(newSubscriptions))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.SubscriptionReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	subscription, err := SubscriptionFromReq(req, nil)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.app.AddSubscription(subscription); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.app.RebuildSubscriptionGroups(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJson(w, http.StatusOK, RespFromSubscription(subscription))
	if err := h.app.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to save config file")
	}
}

func (h *Handler) DeleteSubscription(w http.ResponseWriter, r *http.Request) {
	id, idx, _, ok := h.findSubscriptionByQueryID(w, r)
	if !ok {
		return
	}

	h.app.RemoveSubscriptionByIndex(idx)
	if err := h.app.RebuildSubscriptionGroups(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Info().Str("id", id.String()).Msg("deleted subscription")

	if err := h.app.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to save config file")
	}
	utils.WriteJson(w, http.StatusOK, nil)
}

func (h *Handler) SyncSubscription(w http.ResponseWriter, r *http.Request) {
	_, _, subscription, ok := h.findSubscriptionByQueryID(w, r)
	if !ok {
		return
	}

	rules, err := subscriptionutils.FetchRules(r.Context(), subscription.URL)
	if err != nil {
		utils.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	subscription.Rules = rules
	subscription.LastUpdate = time.Now().UnixMilli()
	if err := h.app.RebuildSubscriptionGroups(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := h.app.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to save config file")
	}
	utils.WriteJson(w, http.StatusOK, RespFromSubscriptionSync(subscription))
}

func (h *Handler) PreviewSubscriptionRules(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if rawURL == "" {
		utils.WriteError(w, http.StatusBadRequest, "url is required")
		return
	}

	rules, err := subscriptionutils.FetchRules(r.Context(), rawURL)
	if err != nil {
		utils.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	utils.WriteJson(w, http.StatusOK, RespFromRules(rules))
}

func (h *Handler) findSubscriptionByQueryID(w http.ResponseWriter, r *http.Request) (intID.ID, int, *models.Subscription, bool) {
	id, err := intID.ParseID(r.URL.Query().Get("id"))
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid subscription id")
		return intID.ID{}, -1, nil, false
	}

	for idx, subscription := range h.app.Subscriptions() {
		if subscription.ID == id {
			return id, idx, subscription, true
		}
	}

	utils.WriteError(w, http.StatusNotFound, "subscription not exist")
	return intID.ID{}, -1, nil, false
}

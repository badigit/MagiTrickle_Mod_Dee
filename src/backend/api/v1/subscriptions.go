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
	var resp types.SubscriptionsRes
	h.app.WithConfigRead(func() {
		resp = RespFromSubscriptions(h.app.Subscriptions())
	})
	utils.WriteJson(w, http.StatusOK, resp)
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

	status, errMsg := 0, ""
	var buildErr error
	var resp types.SubscriptionsRes
	h.app.WithConfigWrite(func() {
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
			newSubscriptions[i], buildErr = SubscriptionFromReq(subscriptionReq, existing)
			if buildErr != nil {
				return
			}
		}

		h.app.ClearSubscriptions()
		for _, subscription := range newSubscriptions {
			if e := h.app.AddSubscription(subscription); e != nil {
				status, errMsg = http.StatusInternalServerError, e.Error()
				return
			}
		}
		if e := h.app.RebuildSubscriptionGroups(); e != nil {
			status, errMsg = http.StatusInternalServerError, e.Error()
			return
		}
		resp = RespFromSubscriptions(newSubscriptions)
	})
	if buildErr != nil {
		utils.WriteError(w, http.StatusBadRequest, buildErr.Error())
		return
	}
	if status != 0 {
		utils.WriteError(w, status, errMsg)
		return
	}

	utils.WriteJson(w, http.StatusOK, resp)
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

	status, errMsg := 0, ""
	var resp types.SubscriptionRes
	h.app.WithConfigWrite(func() {
		if e := h.app.AddSubscription(subscription); e != nil {
			status, errMsg = http.StatusInternalServerError, e.Error()
			return
		}
		if e := h.app.RebuildSubscriptionGroups(); e != nil {
			status, errMsg = http.StatusInternalServerError, e.Error()
			return
		}
		resp = RespFromSubscription(subscription)
	})
	if status != 0 {
		utils.WriteError(w, status, errMsg)
		return
	}

	utils.WriteJson(w, http.StatusOK, resp)
	if err := h.app.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to save config file")
	}
}

func (h *Handler) DeleteSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := intID.ParseID(r.URL.Query().Get("id"))
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	status, errMsg := 0, ""
	h.app.WithConfigWrite(func() {
		// Резолв индекса по ID внутри лока (mt-q5m/mt-6q1: idx на чужом снимке).
		idx := -1
		for i, s := range h.app.Subscriptions() {
			if s.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			status, errMsg = http.StatusNotFound, "subscription not exist"
			return
		}
		h.app.RemoveSubscriptionByIndex(idx)
		if e := h.app.RebuildSubscriptionGroups(); e != nil {
			status, errMsg = http.StatusInternalServerError, e.Error()
			return
		}
	})
	if status != 0 {
		utils.WriteError(w, status, errMsg)
		return
	}
	log.Info().Str("id", id.String()).Msg("deleted subscription")

	if err := h.app.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to save config file")
	}
	utils.WriteJson(w, http.StatusOK, nil)
}

func (h *Handler) SyncSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := intID.ParseID(r.URL.Query().Get("id"))
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	// URL резолвим под RLock, фетч — ВНЕ лока (сетевой I/O не держит датапас).
	var url string
	found := false
	h.app.WithConfigRead(func() {
		for _, s := range h.app.Subscriptions() {
			if s.ID == id {
				url, found = s.URL, true
				break
			}
		}
	})
	if !found {
		utils.WriteError(w, http.StatusNotFound, "subscription not exist")
		return
	}

	rules, err := subscriptionutils.FetchRules(r.Context(), url)
	if err != nil {
		utils.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	status, errMsg := 0, ""
	var resp types.SubscriptionSyncRes
	h.app.WithConfigWrite(func() {
		var subscription *models.Subscription
		for _, s := range h.app.Subscriptions() {
			if s.ID == id {
				subscription = s
				break
			}
		}
		if subscription == nil {
			status, errMsg = http.StatusNotFound, "subscription not exist"
			return
		}
		subscription.Rules = rules
		subscription.LastUpdate = time.Now().UnixMilli()
		if e := h.app.RebuildSubscriptionGroups(); e != nil {
			status, errMsg = http.StatusInternalServerError, e.Error()
			return
		}
		resp = RespFromSubscriptionSync(subscription)
	})
	if status != 0 {
		utils.WriteError(w, status, errMsg)
		return
	}

	if err := h.app.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to save config file")
	}
	utils.WriteJson(w, http.StatusOK, resp)
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

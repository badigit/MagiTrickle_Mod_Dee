package v1

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"magitrickle/api/utils"
	"magitrickle/api/v1/types"
	"magitrickle/app"
	"magitrickle/diagnostics"
	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/updater"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

// Handler предоставляет набор методов для обработки API запросов.
type Handler struct {
	app app.Main
}

// NewHandler создаёт новый обработчик для API v1.
func NewHandler(a app.Main) *Handler {
	return &Handler{app: a}
}

// NetfilterDHook
//
//	@Summary		Хук эвента netfilter.d
//	@Description	Эмитирует хук эвента netfilter.d
//	@Tags			hooks
//	@Accept			json
//	@Produce		json
//	@Param			json	body		types.NetfilterDHookReq	true	"Тело запроса"
//	@Success		200
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/system/hooks/netfilterd [post]
func (h *Handler) NetfilterDHook(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.NetfilterDHookReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Debug().
		Str("type", req.Type).
		Str("table", req.Table).
		Msg("received netfilter.d event")
	err = h.app.ForceCommitIPTables()
	if err != nil {
		log.Error().Err(err).Msg("error fixing iptables after netfilter.d")
	}
}

// ListInterfaces
//
//	@Summary		Получить список интерфейсов
//	@Description	Возвращает список интерфейсов
//	@Tags			config
//	@Produce		json
//	@Success		200		{object}	types.InterfacesRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/system/interfaces [get]
func (h *Handler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := h.app.ListInterfaces()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get interfaces: %w", err).Error())
		return
	}
	res := make([]types.InterfaceRes, 0, len(interfaces)+3)
	res = append(res, types.InterfaceRes{ID: models.InterfaceDirect, Active: true})
	res = append(res, types.InterfaceRes{ID: "blackhole", Active: true})
	for _, iface := range interfaces {
		active := iface.Flags&net.FlagUp != 0
		ip := ""
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
				break
			}
		}
		res = append(res, types.InterfaceRes{ID: iface.Name, Active: active, IP: ip})
	}
	// Add redir-tproxy as a virtual interface entry (only if TProxyPort is configured)
	tproxyPort := h.app.Config().Netfilter.TProxyPort
	if tproxyPort > 0 {
		hasTPROXYGroups := false
		for _, g := range h.app.Groups() {
			if g.Model().EffectiveRouteMode() == models.RouteModeTProxy && g.Model().Enable {
				hasTPROXYGroups = true
				break
			}
		}
		res = append(res, types.InterfaceRes{
			ID:     models.InterfaceTProxy,
			Active: hasTPROXYGroups,
			IP:     fmt.Sprintf("redir-port:%d", tproxyPort),
		})
	}
	utils.WriteJson(w, http.StatusOK, types.InterfacesRes{Interfaces: res})
}

// GetExternalIP checks the external IP for a given interface or redir-tproxy.
func (h *Handler) GetExternalIP(w http.ResponseWriter, r *http.Request) {
	ifaceID := chi.URLParam(r, "interfaceID")

	var client *http.Client
	timeout := 10 * time.Second

	switch {
	case ifaceID == models.InterfaceTProxy:
		utils.WriteJson(w, http.StatusOK, map[string]string{"ip": ""})
		return
	case ifaceID == "blackhole":
		utils.WriteJson(w, http.StatusOK, map[string]string{"ip": "0.0.0.0"})
		return
	case ifaceID == models.InterfaceDirect:
		utils.WriteJson(w, http.StatusOK, map[string]string{"ip": ""})
		return
	default:
		// Bind to the specific network interface
		iface, err := net.InterfaceByName(ifaceID)
		if err != nil {
			utils.WriteError(w, http.StatusNotFound, fmt.Sprintf("interface not found: %s", ifaceID))
			return
		}
		addrs, _ := iface.Addrs()
		var localAddr *net.TCPAddr
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				localAddr = &net.TCPAddr{IP: ipnet.IP}
				break
			}
		}
		if localAddr == nil {
			utils.WriteError(w, http.StatusBadRequest, fmt.Sprintf("no IPv4 address on interface %s", ifaceID))
			return
		}
		dialer := &net.Dialer{
			Timeout:   timeout,
			LocalAddr: localAddr,
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = syscall.BindToDevice(int(fd), ifaceID)
				})
			},
		}
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
			},
		}
	}

	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		// Fallback to HTTP if TLS fails through redir
		if strings.Contains(err.Error(), "tls") || ifaceID == models.InterfaceTProxy {
			resp, err = client.Get("http://api.ipify.org")
		}
		if err != nil {
			utils.WriteError(w, http.StatusBadGateway, fmt.Sprintf("failed to get external IP: %v", err))
			return
		}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		utils.WriteError(w, http.StatusBadGateway, "failed to read response")
		return
	}
	utils.WriteJson(w, http.StatusOK, map[string]string{"ip": strings.TrimSpace(string(body))})
}

// ListInterfaceAliases
//
//	@Summary		Получить список алиасов интерфейсов
//	@Description	Возвращает список алиасов интерфейсов
//	@Tags			config
//	@Produce		json
//	@Success		200		{object}	map[string]string
//	@Router			/api/v1/system/interfaces/aliases [get]
func (h *Handler) ListInterfaceAliases(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, http.StatusOK, h.app.InterfaceAliases())
}

// SaveInterfaceAliases
//
//	@Summary		Сохранить алиасы интерфейсов
//	@Description	Сохраняет алиасы интерфейсов
//	@Tags			config
//	@Accept			json
//	@Produce		json
//	@Param			save	query		bool				false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		map[string]string	true	"Тело запроса"
//	@Success		200
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/system/interfaces/aliases [post]
func (h *Handler) SaveInterfaceAliases(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[map[string]string](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.app.SetInterfaceAliases(req)
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveInterfaceConfig(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save config: %v", err))
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, nil)
}

// SaveConfig
//
//	@Summary		Сохранить конфигурацию
//	@Description	Сохраняет текущую конфигурацию в постоянную память
//	@Tags			config
//	@Produce		json
//	@Success		200
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/system/config/save [post]
func (h *Handler) SaveConfig(w http.ResponseWriter, r *http.Request) {
	if err := h.app.SaveConfig(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save config: %v", err))
	}
}

// GetGroups
//
//	@Summary		Получить список групп
//	@Description	Возвращает список групп
//	@Tags			groups
//	@Produce		json
//	@Param			with_rules	query		bool	false	"Возвращать группы с их правилами"
//	@Success		200			{object}	types.GroupsRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups [get]
func (h *Handler) GetGroups(w http.ResponseWriter, r *http.Request) {
	withRules := r.URL.Query().Get("with_rules") == "true"
	withIPCount := r.URL.Query().Get("with_ip_count") == "true"
	appGroups := h.app.Groups()
	modelGroups := make([]*models.Group, len(appGroups))
	for i, g := range appGroups {
		modelGroups[i] = g.Model()
	}
	res := RespFromGroups(modelGroups, withRules)
	if withIPCount && res.Groups != nil {
		for i, g := range appGroups {
			count := 0
			if ipv4, err := g.ListIPv4Subnets(); err == nil {
				count += len(ipv4)
			}
			if ipv6, err := g.ListIPv6Subnets(); err == nil {
				count += len(ipv6)
			}
			(*res.Groups)[i].IPCount = &count
		}
	}
	utils.WriteJson(w, http.StatusOK, res)
}

// PutGroups
//
//	@Summary		Обновить список групп
//	@Description	Обновляет список групп
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.GroupsReq	true	"Тело запроса"
//	@Success		200			{object}	types.GroupsRes
//	@Failure		400			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups [put]
func (h *Handler) PutGroups(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.GroupsReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Groups == nil {
		utils.WriteError(w, http.StatusBadRequest, "no groups in request")
		return
	}
	for _, g := range h.app.Groups() {
		_ = g.Disable()
	}
	newGroups := make([]*models.Group, len(*req.Groups))
	for i, gReq := range *req.Groups {
		var existing *models.Group
		for _, g := range h.app.Groups() {
			if gReq.ID != nil && g.Model().ID == *gReq.ID {
				existing = g.Model()
				break
			}
		}
		newGroups[i], err = GroupFromReq(gReq, existing)
		if err != nil {
			utils.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	h.app.ClearGroups()
	var addErrors []string
	for _, grp := range newGroups {
		if err := h.app.AddGroup(grp); err != nil {
			log.Error().Err(err).Str("group", grp.Name).Msg("failed to add group")
			addErrors = append(addErrors, fmt.Sprintf("%s: %v", grp.Name, err))
		}
	}
	h.app.SyncAllGroups()
	if len(addErrors) > 0 {
		utils.WriteJson(w, http.StatusOK, map[string]any{
			"groups": RespFromGroups(newGroups, true).Groups,
			"errors": addErrors,
		})
	} else {
		utils.WriteJson(w, http.StatusOK, RespFromGroups(newGroups, true))
	}
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// CreateGroup
//
//	@Summary		Создать группу
//	@Description	Создает группу
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.GroupReq	true	"Тело запроса"
//	@Success		200			{object}	types.GroupRes
//	@Failure		400			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups [post]
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.GroupReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	group, err := GroupFromReq(req, nil)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.app.AddGroup(group); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.app.SyncAllGroups()
	utils.WriteJson(w, http.StatusOK, RespFromGroup(group, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetGroup
//
//	@Summary		Получить группу
//	@Description	Возвращает запрошенную группу
//	@Tags			groups
//	@Produce		json
//	@Param			groupID		path		string	true	"ID группы"
//	@Param			with_rules	query		bool	false	"Возвращать группу с её правилами"
//	@Success		200			{object}	types.GroupRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [get]
func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	withRules := r.URL.Query().Get("with_rules") == "true"
	group := h.app.Groups()[groupIdx].Model()
	utils.WriteJson(w, http.StatusOK, RespFromGroup(group, withRules))
}

// PutGroup
//
//	@Summary		Обновить группу
//	@Description	Обновляет запрошенную группу
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.GroupReq	true	"Тело запроса"
//	@Success		200			{object}	types.GroupRes
//	@Failure		400			{object}	types.ErrorRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [put]
func (h *Handler) PutGroup(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.GroupReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]

	enabled := groupWrapper.Enabled()
	if enabled {
		if err := groupWrapper.Disable(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable group: %v", err))
			return
		}
	}

	updatedGroup, err := GroupFromReq(req, groupWrapper.Model())
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if enabled {
		if err := groupWrapper.Enable(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable group: %v", err))
			return
		}
		// Sync всех групп: изменённая группа получит новые IP,
		// остальные — удалят stale IP из перенесённых правил.
		h.app.SyncAllGroups()
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroup(updatedGroup, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// DeleteGroup
//
//	@Summary		Удалить группу
//	@Description	Удаляет запрошенную группу
//	@Tags			groups
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Param			save	query		bool	false	"Сохранить изменения в конфигурационный файл"
//	@Success		200
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [delete]
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	if groupWrapper.Enabled() {
		if err := groupWrapper.Disable(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable group: %v", err))
			return
		}
	}
	h.app.RemoveGroupByIndex(groupIdx)
	h.app.SyncAllGroups()
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetRules
//
//	@Summary		Получить список правил
//	@Description	Возвращает список правил
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Success		200			{object}	types.RulesRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [get]
func (h *Handler) GetRules(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	rules := h.app.Groups()[groupIdx].Model().Rules
	utils.WriteJson(w, http.StatusOK, RespFromRules(rules))
}

// PutRules
//
//	@Summary		Обновить список правил
//	@Description	Обновляет список правил
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.RulesReq	true	"Тело запроса"
//	@Success		200			{object}	types.RulesRes
//	@Failure		400			{object}	types.ErrorRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [put]
func (h *Handler) PutRules(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.RulesReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Rules == nil {
		utils.WriteError(w, http.StatusBadRequest, "no rules in request")
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	newRules := make([]*models.Rule, len(*req.Rules))
	for i, rr := range *req.Rules {
		id := intID.RandomID()
		if rr.ID != nil {
			found := false
			for _, oldRule := range groupWrapper.Model().Rules {
				if oldRule.ID == *rr.ID {
					id = *rr.ID
					found = true
					break
				}
			}
			if !found {
				utils.WriteError(w, http.StatusNotFound, "rule not found")
				return
			}
		}
		newRules[i] = &models.Rule{
			ID:     id,
			Name:   rr.Name,
			Type:   rr.Type,
			Rule:   rr.Rule,
			Enable: rr.Enable,
		}
	}
	groupWrapper.Model().Rules = newRules
	if enabled {
		h.app.SyncAllGroups()
	}
	utils.WriteJson(w, http.StatusOK, RespFromRules(newRules))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// CreateRule
//
//	@Summary		Создать правило
//	@Description	Создает правило
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.RuleReq	true	"Тело запроса"
//	@Success		200			{object}	types.RuleRes
//	@Failure		400			{object}	types.ErrorRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [post]
func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.RuleReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	rule, err := RuleFromReq(req, groupWrapper.Model().Rules)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupWrapper.Model().Rules = append(groupWrapper.Model().Rules, rule)
	if enabled {
		h.app.SyncAllGroups()
	}
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetRule
//
//	@Summary		Получить правило
//	@Description	Возвращает запрошенное правило
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Param			ruleID	path		string	true	"ID правила"
//	@Success		200			{object}	types.RuleRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [get]
func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := h.app.Groups()[groupIdx].Model().Rules[ruleIdx]
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
}

// PutRule
//
//	@Summary		Обновить правило
//	@Description	Обновляет запрошенное правило
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			ruleID	path		string			true	"ID правила"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.RuleReq	true	"Тело запроса"
//	@Success		200			{object}	types.RuleRes
//	@Failure		400			{object}	types.ErrorRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [put]
func (h *Handler) PutRule(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.RuleReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := groupWrapper.Model().Rules[ruleIdx]
	rule.Name = req.Name
	rule.Type = req.Type
	rule.Rule = req.Rule
	rule.Enable = req.Enable

	if enabled {
		h.app.SyncAllGroups()
	}
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// StartDNSCapture запускает захват DNS-запросов.
func (h *Handler) StartDNSCapture(w http.ResponseWriter, r *http.Request) {
	var filterIP string
	if body, err := utils.ReadJson[struct {
		FilterIP string `json:"filter_ip"`
	}](r); err == nil {
		filterIP = strings.TrimSpace(body.FilterIP)
	}
	h.app.DNSCapture().Start(filterIP)
	utils.WriteJson(w, http.StatusOK, h.app.DNSCapture().Status(false))
}

// StopDNSCapture останавливает захват DNS-запросов.
func (h *Handler) StopDNSCapture(w http.ResponseWriter, r *http.Request) {
	h.app.DNSCapture().Stop()
	utils.WriteJson(w, http.StatusOK, h.app.DNSCapture().Status(true))
}

// GetDNSCaptureStatus возвращает статус захвата DNS-запросов.
func (h *Handler) GetDNSCaptureStatus(w http.ResponseWriter, r *http.Request) {
	withDomains := r.URL.Query().Get("domains") == "true"
	utils.WriteJson(w, http.StatusOK, h.app.DNSCapture().Status(withDomains))
}

// SetEnabled
//
//	@Summary		Глобальный тумблер MagiTrickle
//	@Description	Включает или выключает захват и маршрутизацию. Когда выключено,
//	                трафик ходит мимо MagiTrickle (DNSOR снят, группы выключены).
//	@Tags			system
//	@Accept			json
//	@Produce		json
//	@Param			json	body		object	true	"{enabled: bool}"
//	@Success		200
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/system/enabled [post]
func (h *Handler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Enabled bool `json:"enabled"`
	}
	body, err := utils.ReadJson[req](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.app.SetEnabled(body.Enabled); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	utils.WriteJson(w, http.StatusOK, map[string]bool{"enabled": h.app.IsRoutingActive()})
}

// GetEnabled
//
//	@Summary		Состояние глобального тумблера
//	@Tags			system
//	@Produce		json
//	@Success		200
//	@Router			/api/v1/system/enabled [get]
func (h *Handler) GetEnabled(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, http.StatusOK, map[string]bool{"enabled": h.app.IsRoutingActive()})
}

// GetSystemInfo
//
//	@Summary		Системная информация
//	@Description	Возвращает время старта процесса и аптайм в секундах.
//	@Tags			system
//	@Produce		json
//	@Success		200
//	@Router			/api/v1/system/info [get]
func (h *Handler) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	startedAt := h.app.StartedAt()
	utils.WriteJson(w, http.StatusOK, map[string]any{
		"started_at":     startedAt.UTC().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(startedAt).Seconds()),
	})
}

// RestartService
//
//	@Summary		Перезапустить сервис
//	@Description	Запускает init.d-скрипт и завершает текущий процесс,
//	                чтобы супервизор поднял свежий magitrickled.
//	@Tags			system
//	@Produce		json
//	@Success		200
//	@Router			/api/v1/system/restart [post]
func (h *Handler) RestartService(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, http.StatusOK, map[string]string{"status": "restarting"})
	h.app.Restart()
}

// GetTProxyStatus возвращает диагностику TPROXY.
func (h *Handler) GetTProxyStatus(w http.ResponseWriter, r *http.Request) {
	port := h.app.Config().Netfilter.TProxyPort
	res := types.TProxyStatusRes{
		Configured: port > 0,
		Port:       port,
	}
	if port > 0 {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err == nil {
			conn.Close()
			res.Listening = true
		}
		for _, g := range h.app.Groups() {
			m := g.Model()
			if m.EffectiveRouteMode() != models.RouteModeTProxy {
				continue
			}
			ipCount := 0
			if ipv4, err := g.ListIPv4Subnets(); err == nil {
				ipCount += len(ipv4)
			}
			if ipv6, err := g.ListIPv6Subnets(); err == nil {
				ipCount += len(ipv6)
			}
			res.Groups = append(res.Groups, types.TProxyGroupStatus{
				ID:      m.ID,
				Name:    m.Name,
				Enable:  m.Enable,
				IPCount: ipCount,
			})
		}
	}
	utils.WriteJson(w, http.StatusOK, res)
}

// RunSpeedtest запускает тест скорости и стримит результаты через SSE.
func (h *Handler) RunSpeedtest(w http.ResponseWriter, r *http.Request) {
	ifaceName := r.URL.Query().Get("interface")
	serverID, _ := strconv.Atoi(r.URL.Query().Get("server_id"))
	parallelLoss := r.URL.Query().Get("parallel_loss") == "true"
	diagnostics.RunSpeedtestStream(w, ifaceName, serverID, parallelLoss)
}

// GetSpeedtestServers возвращает список доступных серверов Speedtest.
func (h *Handler) GetSpeedtestServers(w http.ResponseWriter, r *http.Request) {
	ifaceName := r.URL.Query().Get("interface")
	search := r.URL.Query().Get("search")
	servers, err := diagnostics.GetServers(ifaceName, search)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get servers: %v", err))
		return
	}

	res := make([]map[string]interface{}, len(servers))
	for i, s := range servers {
		res[i] = map[string]interface{}{
			"id":       s.ID,
			"name":     s.Name,
			"country":  s.Country,
			"sponsor":  s.Sponsor,
			"distance": s.Distance,
			"latency":  s.Latency.Milliseconds(),
		}
	}
	utils.WriteJson(w, http.StatusOK, res)
}

// DeleteRule
//
//	@Summary		Удалить правило
//	@Description	Удаляет запрошенное правило
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Param			ruleID	path		string	true	"ID правила"
//	@Param			save	query		bool	false	"Сохранить изменения в конфигурационный файл"
//	@Success		200
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [delete]
func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	groupWrapper.Model().Rules = append(groupWrapper.Model().Rules[:ruleIdx], groupWrapper.Model().Rules[ruleIdx+1:]...)
	if enabled {
		h.app.SyncAllGroups()
	}
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// CheckUpdate
//
//	@Summary		Проверка обновлений
//	@Description	Проверяет наличие новых версий форка
//	@Tags			system
//	@Produce		json
//	@Success		200
//	@Router			/api/v1/system/update/check [get]
func (h *Handler) CheckUpdate(w http.ResponseWriter, r *http.Request) {
	newVer, err := updater.CheckForUpdates()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to check for updates: %v", err))
		return
	}
	utils.WriteJson(w, http.StatusOK, map[string]any{
		"available_version": newVer,
	})
}

// RunUpdate
//
//	@Summary		Запуск обновления
//	@Description	Скачивает и устанавливает обновление
//	@Tags			system
//	@Produce		json
//	@Success		200
//	@Router			/api/v1/system/update/run [post]
func (h *Handler) RunUpdate(w http.ResponseWriter, r *http.Request) {
	if err := updater.RunUpdate(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to start update: %v", err))
		return
	}
	utils.WriteJson(w, http.StatusOK, map[string]any{"status": "ok"})
}

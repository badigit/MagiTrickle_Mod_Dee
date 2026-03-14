package v1

import (
	"context"
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
	"magitrickle/models"
	"magitrickle/utils/intID"

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
	res := make([]types.InterfaceRes, 0, len(interfaces)+2)
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
	// Add redir-tproxy as a virtual interface entry
	tproxyPort := h.app.Config().Netfilter.TProxyPort
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
	utils.WriteJson(w, http.StatusOK, types.InterfacesRes{Interfaces: res})
}

// GetExternalIP checks the external IP for a given interface or redir-tproxy.
func (h *Handler) GetExternalIP(w http.ResponseWriter, r *http.Request) {
	ifaceID := chi.URLParam(r, "interfaceID")

	var client *http.Client
	timeout := 10 * time.Second

	switch {
	case ifaceID == models.InterfaceTProxy:
		// Route through mihomo SOCKS5 proxy to check exit IP
		socksAddr := "127.0.0.1:7890"
		dialer := &net.Dialer{Timeout: timeout}
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// SOCKS5 CONNECT handshake
					conn, err := dialer.DialContext(ctx, "tcp", socksAddr)
					if err != nil {
						return nil, err
					}
					// Auth: no auth
					if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
						conn.Close()
						return nil, err
					}
					buf := make([]byte, 2)
					if _, err := io.ReadFull(conn, buf); err != nil {
						conn.Close()
						return nil, err
					}
					if buf[0] != 0x05 || buf[1] != 0x00 {
						conn.Close()
						return nil, fmt.Errorf("socks5 auth failed")
					}
					// CONNECT request (domain)
					host, port, _ := net.SplitHostPort(addr)
					portNum, _ := strconv.Atoi(port)
					req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
					req = append(req, []byte(host)...)
					req = append(req, byte(portNum>>8), byte(portNum))
					if _, err := conn.Write(req); err != nil {
						conn.Close()
						return nil, err
					}
					resp := make([]byte, 10)
					if _, err := io.ReadFull(conn, resp); err != nil {
						conn.Close()
						return nil, err
					}
					if resp[1] != 0x00 {
						conn.Close()
						return nil, fmt.Errorf("socks5 connect failed: %d", resp[1])
					}
					return conn, nil
				},
			},
		}
	case ifaceID == "blackhole":
		utils.WriteJson(w, http.StatusOK, map[string]string{"ip": "0.0.0.0"})
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
	appGroups := h.app.Groups()
	modelGroups := make([]*models.Group, len(appGroups))
	for i, g := range appGroups {
		modelGroups[i] = g.Model()
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroups(modelGroups, withRules))
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
	for _, grp := range newGroups {
		if err := h.app.AddGroup(grp); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroups(newGroups, true))
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
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
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
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
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
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
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
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
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
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

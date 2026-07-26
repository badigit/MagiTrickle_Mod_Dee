package models

import "time"

type AppConfig struct {
	Enabled           bool
	HTTPWeb           AppConfigHTTPWeb
	DNSProxy          AppConfigDNSProxy
	Netfilter         AppConfigNetfilter
	Link              []string
	ShowAllInterfaces bool
	LogLevel          string
}

type AppConfigHTTPWeb struct {
	Enabled bool
	Auth    AppConfigAuth
	Host    AppConfigHTTPWebServer
	Skin    string
}

type AppConfigAuth struct {
	Enabled bool
}

type AppConfigHTTPWebServer struct {
	Address string
	Port    uint16
}

type AppConfigDNSProxy struct {
	Host             AppConfigDNSProxyServer
	Upstream         AppConfigDNSProxyServer
	FallbackUpstream *AppConfigDNSProxyServer // если задан — out-of-group домены идут сюда (минуя primary)
	DisableRemap53   bool
	DisableFakePTR   bool
	DisableDropAAAA  bool
	MaxIdleConns     uint
	MaxConcurrent    uint
	Timeout          time.Duration
	// ClientTTLCap ограничивает TTL, отдаваемый КЛИЕНТУ в A/AAAA/CNAME-ответах
	// (секунды). 0 = не капать. Нужен, чтобы клиентский DNS-кэш не переживал
	// запись в ipset: иначе клиент шлёт на запомненный IP не переспрашивая DNS,
	// ipset остывает, и новый коннект уходит direct мимо прокси (mt-240/mt-9g7).
	// Cap НЕ влияет на TTL записи в ipset — там всегда оригинальный origTTL+AdditionalTTL.
	ClientTTLCap uint32
	// PersistCache включает персист recordsCache на диск между запусками
	// (mt-pqa): снапшот пишется раз в 5 мин при изменениях + на shutdown,
	// загружается на старте для мгновенного прогрева ipset. Выключено по
	// умолчанию (mt-0cf): при ClientTTLCap>0 ipset и так самовосстанавливается
	// за ClientTTLCap секунд при ЛЮБОЙ потере (не только рестарте), а после
	// перезапуска пользователь обычно ждёт чистый старт, а не подхват старого
	// состояния. Персист даёт лишь мгновенность при ПЛАНОВОМ рестарте ценой
	// постоянных записей на флеш (~50МБ/сутки при активном трафике).
	PersistCache bool
}

type AppConfigDNSProxyServer struct {
	Address string
	Port    uint16
}

type AppConfigNetfilter struct {
	IPTables            AppConfigIPTables
	IPSet               AppConfigIPSet
	DisableIPv4         bool
	DisableIPv6         bool
	StartMarkTableIndex uint32
	TProxyPort          uint16
}

type AppConfigIPTables struct {
	ChainPrefix string
}

type AppConfigIPSet struct {
	TablePrefix   string
	AdditionalTTL uint32
}

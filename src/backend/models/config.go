package models

import "time"

type AppConfig struct {
	Enabled           bool
	HTTPWeb           AppConfigHTTPWeb
	DNSProxy          AppConfigDNSProxy
	ClientRouting     AppConfigClientRouting
	Netfilter         AppConfigNetfilter
	Link              []string
	ShowAllInterfaces bool
	LogLevel          string
}

const ClientRoutingModeExclude = "exclude"

type AppConfigClientRouting struct {
	Mode           string   `json:"mode"`
	SourceNetworks []string `json:"source_networks"`
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

// Режимы арбитража direct-групп (mt-n4b).
//
// DirectPriorityAbsolute — дефолт и поведение с .15: direct-цепочка встаёт
// первой в PREROUTING, поэтому direct выигрывает любой overlap по IP, где бы
// группа ни стояла в списке.
//
// DirectPriorityByOrder — «как раньше»: direct стоит в общей очереди по своему
// месту в списке групп, поэтому группа выше выигрывает overlap, а широкая
// direct-группа внизу работает catch-all'ом. Это НЕ возврат бага mt-my3:
// цепочка по-прежнему терминирует обход ACCEPT'ом, меняется только позиция.
const (
	DirectPriorityAbsolute = "absolute"
	DirectPriorityByOrder  = "byOrder"
)

type AppConfigNetfilter struct {
	IPTables            AppConfigIPTables
	IPSet               AppConfigIPSet
	DisableIPv4         bool
	DisableIPv6         bool
	StartMarkTableIndex uint32
	TProxyPort          uint16
	DirectPriority      string
}

type AppConfigIPTables struct {
	ChainPrefix string
}

type AppConfigIPSet struct {
	TablePrefix   string
	AdditionalTTL uint32
}

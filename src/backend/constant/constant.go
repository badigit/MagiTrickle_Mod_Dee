package constant

import (
	"time"

	"magitrickle/models"
)

var DefaultAppConfig = models.AppConfig{
	Enabled: true,
	DNSProxy: models.AppConfigDNSProxy{
		Host:            models.AppConfigDNSProxyServer{Address: "[::]", Port: 3553},
		Upstream:        models.AppConfigDNSProxyServer{Address: "127.0.0.1", Port: 53},
		DisableRemap53:  false,
		DisableFakePTR:  false,
		DisableDropAAAA: false,
		MaxIdleConns:    10,
		MaxConcurrent:   100,
		Timeout:         5000 * time.Millisecond,
		// Капаем клиентский DNS TTL до 300с, чтобы кэш ОС/приложений не переживал
		// запись в ipset (mt-9g7). На TTL самой ipset-записи не влияет. 300 —
		// баланс: запас против ipset-жизни (86400+) ~300×, самовосстановление
		// после потери ipset ≤5 мин (ср. KVAS: max-ttl=3600 при тех же 86400).
		ClientTTLCap: 300,
		// Выключено по умолчанию (mt-0cf): при ClientTTLCap>0 ipset и так
		// самовосстанавливается за ClientTTLCap секунд при любой потере, а
		// после рестарта ожидаем чистый старт, а не подхват старого состояния.
		PersistCache: false,
	},
	HTTPWeb: models.AppConfigHTTPWeb{
		Enabled: true,
		Auth: models.AppConfigAuth{
			Enabled: false,
		},
		Host: models.AppConfigHTTPWebServer{
			Address: "[::]",
			Port:    8080,
		},
		Skin: "default",
	},
	Netfilter: models.AppConfigNetfilter{
		IPTables: models.AppConfigIPTables{
			ChainPrefix: "MT_",
		},
		IPSet: models.AppConfigIPSet{
			TablePrefix: "mt_",
			// 24ч: ipset-запись живёт долго после последнего DNS-запроса через
			// роутер. Дёшево (~50Б/запись) и закрывает класс «клиент помнит IP,
			// ipset остыл» для клиентов с собственным IP-кэшем (mt-9g7).
			AdditionalTTL: 86400,
		},
		DisableIPv4:         false,
		DisableIPv6:         false,
		StartMarkTableIndex: 0x4D616769, // Magi
		TProxyPort:          5001,
	},
	Link:              []string{"br0"},
	ShowAllInterfaces: false,
	LogLevel:          "info",
}

var (
	Version   = "unattached"
	BuildDate = ""
)

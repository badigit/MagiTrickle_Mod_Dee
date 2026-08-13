package models

// LookupWhy* — причины, по которым группа выиграла арбитраж домена или IP.
// Живут в models, потому что их производят три слоя сразу: ядро (searchDomain),
// API-типы (/api/v1/lookup) и потребители ответа. Одна копия строк гарантирует,
// что объяснение, показанное пользователю, называется так же, как решение,
// принятое роутингом.
const (
	// LookupWhyExact — точное domain-правило совпало с самим запросом.
	LookupWhyExact = "exact"
	// LookupWhyNamespace — запрос пойман родительским namespace-правилом.
	LookupWhyNamespace = "namespace"
	// LookupWhyWildcard — совпал wildcard-шаблон (слой после trie).
	LookupWhyWildcard = "wildcard"
	// LookupWhyRegex — совпало regex-правило (последний фолбэк).
	LookupWhyRegex = "regex"
	// LookupWhyIpsetFirst — для IP-запроса: первая по порядку группа, в чьём
	// ipset этот адрес уже лежит. Это и есть фактический исход для пакета.
	LookupWhyIpsetFirst = "ipset-first"
	// LookupWhySubnet — для IP-запроса: адрес попал в подсеть правила, но в
	// ipset его ещё нет (см. Winner.Pending).
	LookupWhySubnet = "subnet"
)

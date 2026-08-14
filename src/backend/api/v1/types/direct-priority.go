package types

// DirectPriority — режим арбитража direct-групп (mt-n4b): absolute (цепочка
// direct первой в PREROUTING, перебивает любые группы) либо byOrder (direct
// стоит по своему месту в списке, широкая direct-группа внизу работает
// catch-all'ом). Отдельный тип, а не голая строка, чтобы у ручки был
// стабильный JSON-контракт: {"mode": "..."}.
type DirectPriority struct {
	Mode string `json:"mode"`
}

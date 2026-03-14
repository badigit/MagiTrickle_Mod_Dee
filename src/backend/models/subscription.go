package models

import "magitrickle/utils/intID"

type Subscription struct {
	ID         intID.ID
	Name       string
	Interface  string
	Enable     bool
	URL        string
	LastUpdate int64
	Interval   int64
	Rules      []*Rule
}

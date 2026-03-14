package config

import "magitrickle/utils/intID"

type Subscription struct {
	ID         intID.ID `yaml:"id"`
	Name       string   `yaml:"name"`
	Interface  string   `yaml:"interface"`
	Enable     *bool    `yaml:"enable"`
	URL        string   `yaml:"url"`
	LastUpdate *int64   `yaml:"last_update"`
	Interval   *int64   `yaml:"interval"`
	Rules      []Rule   `yaml:"rules"`
}

package magitrickle

import (
	"context"
	"fmt"
	"time"

	"magitrickle/models"
	subscriptionutils "magitrickle/utils/subscriptions"

	"github.com/rs/zerolog/log"
)

const subscriptionRuntimeGroupColor = "#ffffff"

func (a *App) routingGroups() []*Group {
	base := *a.groups.Load()
	subscriptionGroups := *a.subscriptionGroups.Load()

	result := make([]*Group, 0, len(base)+len(subscriptionGroups))
	result = append(result, base...)
	result = append(result, subscriptionGroups...)
	return result
}

func (a *App) RebuildSubscriptionGroups() error {
	oldGroups := *a.subscriptionGroups.Load()
	if a.routingActive.Load() {
		for _, group := range oldGroups {
			_ = group.Disable()
		}
	}

	subscriptions := a.Subscriptions()
	newGroups := make([]*Group, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		groupModel := &models.Group{
			ID:        subscription.ID,
			Name:      subscription.Name,
			Color:     subscriptionRuntimeGroupColor,
			Interface: subscription.Interface,
			Enable:    subscription.Enable,
			Rules:     subscription.Rules,
		}

		group, err := newGroupWithRuntimeID(groupModel, a, "s"+subscription.ID.String())
		if err != nil {
			return fmt.Errorf("failed to create runtime subscription group: %w", err)
		}
		newGroups = append(newGroups, group)
	}

	a.subscriptionGroups.Store(&newGroups)

	if !a.routingActive.Load() || a.nfHelper == nil {
		return nil
	}

	for _, group := range newGroups {
		if err := group.Enable(); err != nil {
			return fmt.Errorf("failed to enable subscription group: %w", err)
		}
	}

	a.SyncAllGroups()
	return nil
}

// rulesEquivalent reports whether two rule lists describe the same set of
// rules. ID and Name are ignored because FetchRules generates a fresh random
// ID on every fetch and Name is not provided by the source format.
func rulesEquivalent(a, b []*models.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x == nil || y == nil {
			if x != y {
				return false
			}
			continue
		}
		if x.Type != y.Type || x.Rule != y.Rule || x.Enable != y.Enable {
			return false
		}
	}
	return true
}

func (a *App) startSubscriptionSyncLoop(ctx context.Context, _ chan error) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.syncDueSubscriptions(ctx); err != nil {
					log.Error().Err(err).Msg("subscription auto-sync failed")
				}
			}
		}
	}()
}

func (a *App) syncDueSubscriptions(ctx context.Context) error {
	now := time.Now()
	changed := false

	for _, subscription := range a.Subscriptions() {
		if !subscription.Enable || subscription.Interval <= 0 || subscription.URL == "" {
			continue
		}

		lastUpdate := time.UnixMilli(subscription.LastUpdate)
		if subscription.LastUpdate > 0 && now.Sub(lastUpdate) < time.Duration(subscription.Interval)*time.Second {
			continue
		}

		rules, err := subscriptionutils.FetchRules(ctx, subscription.URL)
		if err != nil {
			log.Error().
				Err(err).
				Str("subscriptionId", subscription.ID.String()).
				Str("url", subscription.URL).
				Msg("failed to auto-sync subscription")
			continue
		}

		if rulesEquivalent(subscription.Rules, rules) {
			// Source unchanged — bump in-memory timestamp so we don't refetch
			// on every ticker, but skip group rebuild and config write to avoid
			// resetting ipsets and flash wear.
			subscription.LastUpdate = now.UnixMilli()
			continue
		}

		subscription.Rules = rules
		subscription.LastUpdate = now.UnixMilli()
		changed = true
	}

	if !changed {
		return nil
	}

	if err := a.RebuildSubscriptionGroups(); err != nil {
		return err
	}
	if err := a.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config after auto-sync: %w", err)
	}

	return nil
}

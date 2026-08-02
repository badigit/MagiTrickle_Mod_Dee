package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/netfilterTools"
)

type fakeClientRoutingApp struct {
	app.Main
	config models.AppConfigClientRouting
}

func (f *fakeClientRoutingApp) ClientRouting() models.AppConfigClientRouting {
	return models.AppConfigClientRouting{
		Mode:           f.config.Mode,
		SourceNetworks: append([]string(nil), f.config.SourceNetworks...),
	}
}

func (f *fakeClientRoutingApp) SetClientRouting(cfg models.AppConfigClientRouting) error {
	normalized, _, err := netfilterTools.NormalizeSourceNetworks(cfg.SourceNetworks)
	if err != nil {
		return err
	}
	f.config = models.AppConfigClientRouting{Mode: cfg.Mode, SourceNetworks: normalized}
	return nil
}

func TestClientRoutingAPI(t *testing.T) {
	fake := &fakeClientRoutingApp{config: models.AppConfigClientRouting{
		Mode:           models.ClientRoutingModeExclude,
		SourceNetworks: []string{"192.168.1.10"},
	}}
	router := NewRouter(fake)

	t.Run("get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/system/client-routing", nil)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
		}
		var got models.AppConfigClientRouting
		if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, fake.config) {
			t.Fatalf("response mismatch: want %#v, got %#v", fake.config, got)
		}
	})

	t.Run("put canonicalizes", func(t *testing.T) {
		body := bytes.NewBufferString(`{"mode":"exclude","source_networks":["192.168.1.99/24","2001:db8::1"]}`)
		req := httptest.NewRequest(http.MethodPut, "/system/client-routing", body)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
		}
		want := []string{"192.168.1.0/24", "2001:db8::1"}
		if !reflect.DeepEqual(fake.config.SourceNetworks, want) {
			t.Fatalf("canonical networks mismatch: want %v, got %v", want, fake.config.SourceNetworks)
		}
	})

	t.Run("put rejects invalid input", func(t *testing.T) {
		body := bytes.NewBufferString(`{"mode":"exclude","source_networks":["device.lan"]}`)
		req := httptest.NewRequest(http.MethodPut, "/system/client-routing", body)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", res.Code, res.Body.String())
		}
	})
}

package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"magitrickle/api/v1/types"
	"magitrickle/app"
	"magitrickle/models"
)

type fakeDirectPriorityApp struct {
	app.Main
	mode    string
	setCall string
	setErr  error
}

func (f *fakeDirectPriorityApp) DirectPriority() string { return f.mode }
func (f *fakeDirectPriorityApp) SetDirectPriority(mode string) error {
	f.setCall = mode
	if f.setErr != nil {
		return f.setErr
	}
	f.mode = mode
	return nil
}

func TestDirectPriorityAPI(t *testing.T) {
	get := func(t *testing.T, a app.Main) types.DirectPriority {
		t.Helper()
		res := httptest.NewRecorder()
		NewRouter(a).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/system/direct-priority", nil))
		if res.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
		}
		var out types.DirectPriority
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	put := func(t *testing.T, a app.Main, body string) *httptest.ResponseRecorder {
		t.Helper()
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/system/direct-priority", bytes.NewReader([]byte(body)))
		NewRouter(a).ServeHTTP(res, req)
		return res
	}

	t.Run("get отдаёт текущий режим", func(t *testing.T) {
		fake := &fakeDirectPriorityApp{mode: models.DirectPriorityAbsolute}
		if got := get(t, fake); got.Mode != models.DirectPriorityAbsolute {
			t.Fatalf("mode = %q, want %q", got.Mode, models.DirectPriorityAbsolute)
		}
	})

	t.Run("put переключает режим", func(t *testing.T) {
		fake := &fakeDirectPriorityApp{mode: models.DirectPriorityAbsolute}
		res := put(t, fake, `{"mode":"byOrder"}`)
		if res.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
		}
		if fake.setCall != models.DirectPriorityByOrder {
			t.Errorf("SetDirectPriority вызван с %q, want %q", fake.setCall, models.DirectPriorityByOrder)
		}
		if got := get(t, fake); got.Mode != models.DirectPriorityByOrder {
			t.Errorf("после put режим = %q", got.Mode)
		}
	})

	// Неизвестный режим обязан быть отвергнут, а не «нормализован» молча:
	// иначе пользователь думает, что переключил, а роутинг остался прежним.
	t.Run("put отвергает неизвестный режим", func(t *testing.T) {
		fake := &fakeDirectPriorityApp{mode: models.DirectPriorityAbsolute}
		res := put(t, fake, `{"mode":"whatever"}`)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body = %s)", res.Code, res.Body.String())
		}
		if fake.setCall != "" {
			t.Errorf("SetDirectPriority не должен вызываться, вызван с %q", fake.setCall)
		}
	})
}

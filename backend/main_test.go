package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCookieHandler(t *testing.T) {
	err := os.Setenv("KEY", "StrongKey")
	if err != nil {
		t.Fatal("Failed to set env variable")
	}

	req, err := http.NewRequest("GET", "/access?GUID=550e8400-e29b-41d4-a716-446655440000", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(access)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	cookies := rr.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "AccessToken" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AccessToken cookie not set")
	}
}

func TestAccessHandler(t *testing.T) {
	err := os.Setenv("KEY", "StrongKey")
	if err != nil {
		t.Fatal("Failed to set env variable")
	}

	req, err := http.NewRequest("GET", "/access?GUID=550e8400-e29b-41d4-a716-446655440000", nil)

	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "AccessToken",
		Value: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaXAiOiIxOTIuMTY4LjAuMTA4IiwiZXhwIjoxNzI1OTg0MjI0LCJ0b2tlbl9pZCI6IjgwOTcwZDQ3LWNjYzQtNDQ2ZC1hMjU4LTRhMGY0M2EzZTRhYSIsInVzZXJfaWQiOiJkMDkwNTI4MC1kZWQ4LTRmOGQtYmU5MS02ZDViZTA0ZWJmZDUifQ.jt7ksfjAgvPHYDohljt17ONF2IbQOKaDMuF0I_vldqDgJwxqWJFjFs69bA2pHvA_tYpKsaiCh0o3S2pvcMnhqA",
	})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(access)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "Access:"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestRefreshHandler(t *testing.T) {
	err := os.Setenv("KEY", "StrongKey")
	if err != nil {
		t.Fatal("Failed to set env variable")
	}

	req, err := http.NewRequest("GET", "/refresh?GUID=550e8400-e29b-41d4-a716-446655440000", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "AccessToken",
		Value: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaXAiOiIxOTIuMTY4LjAuMTA4IiwiZXhwIjoxNzI1OTg0MjI0LCJ0b2tlbl9pZCI6IjgwOTcwZDQ3LWNjYzQtNDQ2ZC1hMjU4LTRhMGY0M2EzZTRhYSIsInVzZXJfaWQiOiJkMDkwNTI4MC1kZWQ4LTRmOGQtYmU5MS02ZDViZTA0ZWJmZDUifQ.jt7ksfjAgvPHYDohljt17ONF2IbQOKaDMuF0I_vldqDgJwxqWJFjFs69bA2pHvA_tYpKsaiCh0o3S2pvcMnhqA",
	})

	req.AddCookie(&http.Cookie{
		Name:  "RefreshToken",
		Value: "DMXNGIAkjREkXWKDnPYyXcP%2FzuHCMx8l1DoFgSCF%2FwBqwmmdax%2BTuSSQmWr64iaI",
	})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(refresh)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

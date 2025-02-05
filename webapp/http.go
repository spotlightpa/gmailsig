package webapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"net/http"

	"github.com/carlmjohnson/resperr"
	"github.com/getsentry/sentry-go"
)

func (app *appEnv) logRoute(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Path
		if r.URL.RawQuery != "" {
			q := r.URL.Query()
			q.Del("code")
			q.Del("state")
			url = url + "?" + q.Encode()
		}
		logger.Printf("[%s] %q - %s", r.Method, url, r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}

func (app *appEnv) replyErr(w http.ResponseWriter, r *http.Request, err error) {
	app.logErr(r.Context(), err)
	code := resperr.StatusCode(err)
	msg := resperr.UserMessage(err)
	http.Error(w, msg, code)
}

func (app *appEnv) logErr(ctx context.Context, err error) {
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		hub.CaptureException(err)
	} else {
		logger.Printf("sentry not in context")
	}

	logger.Printf("err: %v", err)
}

const (
	tokenCookie       = "google-token"
	stateCookie       = "google-state"
	redirectURLCookie = "google-redirect-url"
	scopesCookie      = "google-scopes"
)

func (app *appEnv) setCookie(w http.ResponseWriter, name string, v interface{}) {
	const oneMonth = 60 * 60 * 24 * 31
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.URLEncoding.EncodeToString(buf.Bytes()),
		MaxAge:   oneMonth,
		HttpOnly: true,
		Secure:   app.isLambda(),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	mac := hmac.New(sha256.New, app.signingSecret)
	mac.Write(buf.Bytes())
	sig := mac.Sum(nil)

	http.SetCookie(w, &http.Cookie{
		Name:     name + "-signed",
		Value:    base64.URLEncoding.EncodeToString(sig),
		MaxAge:   oneMonth,
		HttpOnly: true,
		Secure:   app.isLambda(),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

}

func (app *appEnv) deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   app.isLambda(),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     name + "-signed",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   app.isLambda(),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}

func (app *appEnv) getCookie(r *http.Request, name string, v interface{}) bool {
	c, err := r.Cookie(name)
	if err != nil {
		return false
	}
	b, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}

	c, err = r.Cookie(name + "-signed")
	if err != nil {
		return false
	}
	cookieHMAC, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, app.signingSecret)
	mac.Write(b)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(cookieHMAC, expectedMAC) {
		return false
	}

	dec := gob.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(v)
	return err == nil
}

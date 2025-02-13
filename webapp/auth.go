package webapp

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/carlmjohnson/resperr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func (app *appEnv) googleClient(r *http.Request, scopes ...string) *http.Client {
	var tok oauth2.Token
	if !app.getCookie(r, tokenCookie, &tok) {
		return nil
	}
	if !tok.Valid() && tok.RefreshToken == "" {
		return nil
	}
	conf := app.googleConfig(scopes...)
	return conf.Client(r.Context(), &tok)
}

func (app *appEnv) googleConfig(scopes ...string) *oauth2.Config {
	u := "http://localhost:53312/app/auth-callback"
	if app.isLambda() {
		u = "https://gmailsig.spotlightpa.org/app/auth-callback"
	}
	return &oauth2.Config{
		ClientID:     app.oauthClientID,
		ClientSecret: app.oauthClientSecret,
		RedirectURL:  u,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}
}

func (app *appEnv) authRedirect(w http.ResponseWriter, r *http.Request, scopes ...string) {
	u := *r.URL
	logger.Println("current url", u)
	app.setCookie(w, redirectURLCookie, &u)

	stateToken := rand.Text()
	app.setCookie(w, stateCookie, stateToken)

	app.setCookie(w, scopesCookie, scopes)

	conf := app.googleConfig(scopes...)
	// Redirect user to Google's consent page to ask for permission
	url := conf.AuthCodeURL(stateToken)
	w.Header().Set("Cache-Control", "no-cache")
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (app *appEnv) authCallback(w http.ResponseWriter, r *http.Request) {
	var state string
	if !app.getCookie(r, stateCookie, &state) {
		app.replyHTMLErr(w, r, resperr.New(http.StatusUnauthorized, "no saved state"))
		return
	}
	app.deleteCookie(w, stateCookie)

	var redirect url.URL
	if !app.getCookie(r, redirectURLCookie, &redirect) {
		app.replyHTMLErr(w, r, resperr.New(http.StatusUnauthorized, "no redirect"))
		return
	}
	app.deleteCookie(w, redirectURLCookie)

	var scopes []string
	if !app.getCookie(r, scopesCookie, &scopes) {
		app.replyHTMLErr(w, r, resperr.New(http.StatusUnauthorized, "no scope"))
		return
	}
	app.deleteCookie(w, scopesCookie)

	if callbackState := r.FormValue("state"); state != callbackState {
		app.replyHTMLErr(w, r, resperr.New(
			http.StatusBadRequest,
			"token %q != %q",
			state, callbackState))
		return
	}
	conf := app.googleConfig(scopes...)
	tok, err := conf.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		app.replyHTMLErr(w, r, err)
		return
	}
	csrf := rand.Text()
	app.setCookie(w, csrfCookie, csrf)
	app.setCookie(w, tokenCookie, &tok)
	redirect.ForceQuery = true

	w2 := httptest.ResponseRecorder{}
	http.Redirect(&w2, r, redirect.String(), http.StatusSeeOther)
	logger.Printf("%q", w2.Result().Header)
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

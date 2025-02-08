package webapp

import (
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"

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
	app.setCookie(w, redirectURLCookie, r.URL)

	stateToken := r.Host + "|" + rand.Text()
	app.setCookie(w, stateCookie, stateToken)

	app.setCookie(w, scopesCookie, scopes)

	conf := app.googleConfig(scopes...)
	// Redirect user to Google's consent page to ask for permission
	url := conf.AuthCodeURL(stateToken)
	w.Header().Set("Cache-Control", "no-cache")
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (app *appEnv) authCallback(w http.ResponseWriter, r *http.Request) {
	// Redirect if necessary for deploy previews
	callbackState := r.FormValue("state")
	host, _, _ := strings.Cut(callbackState, "|")
	if host != r.Host && strings.HasSuffix(host, "--gmailsig.netlify.app") {
		u := *r.URL
		u.Host = host
		logger.Printf("redirecting log in to %q", host)
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
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

	if state != callbackState {
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
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

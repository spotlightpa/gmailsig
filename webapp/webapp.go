package webapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spotlightpa/gmailsig/static"

	"github.com/carlmjohnson/flagx"
	"github.com/carlmjohnson/gateway"
	"github.com/carlmjohnson/requests"
	"github.com/carlmjohnson/resperr"
	"github.com/earthboundkid/versioninfo/v2"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
)

const AppName = "Gmail Sig"

func CLI(args []string) error {
	var app appEnv
	err := app.ParseArgs(args)
	if err != nil {
		return err
	}
	if err = app.Exec(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	return err
}

func (app *appEnv) ParseArgs(args []string) error {
	fl := flag.NewFlagSet(AppName, flag.ContinueOnError)
	fl.Usage = func() {
		fmt.Fprintf(fl.Output(), `gmailsig - %s

Set Gmail signatures for users

Usage:

	gmailsig [options]

Options:
`, versioninfo.Version)
		fl.PrintDefaults()
	}
	fl.IntVar(&app.port, "port", -1, "specify a port to use http rather than AWS Lambda")
	sentryDSN := fl.String("sentry-dsn", "", "DSN `pseudo-URL` for Sentry")
	fl.StringVar(&app.oauthClientID, "client-id", "", "Google `Oauth client ID`")
	fl.StringVar(&app.oauthClientSecret, "client-secret", "", "Google `Oauth client secret`")
	secret := fl.String("signing-secret", "", "`secret` for HMAC cookie signing")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if err := flagx.ParseEnv(fl, AppName); err != nil {
		return err
	}
	app.signingSecret = []byte(*secret)
	logger.SetPrefix(AppName + " ")
	logger.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := app.initSentry(*sentryDSN); err != nil {
		return err
	}
	return nil
}

var logger = log.Default()

type appEnv struct {
	port              int
	oauthClientID     string
	oauthClientSecret string
	signingSecret     []byte
}

func (app *appEnv) Exec() (err error) {
	listener := gateway.ListenAndServe
	var portStr string
	if app.isLambda() {
		portStr = os.Getenv("DEPLOY_PRIME_URL")
	} else {
		portStr = fmt.Sprintf(":%d", app.port)
		listener = http.ListenAndServe
	}

	logger.Printf("starting on %s", portStr)
	return listener(portStr, app.routes())
}

func (app *appEnv) initSentry(dsn string) error {
	var transport sentry.Transport
	if app.isLambda() {
		logger.Printf("setting sentry sync with timeout")
		transport = &sentry.HTTPSyncTransport{Timeout: 5 * time.Second}
	}
	if dsn == "" {
		logger.Printf("no Sentry DSN")
		return nil
	}
	return sentry.Init(sentry.ClientOptions{
		Dsn:       dsn,
		Release:   versioninfo.Revision,
		Transport: transport,
	})
}

func (app *appEnv) isLambda() bool {
	return app.port == -1
}

func (app *appEnv) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write(static.FourOhFour)
	})
	if app.isLambda() {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFileFS(w, r, static.FS, "index.html")
		})
		fs.WalkDir(static.FS, ".", func(path string, d fs.DirEntry, err error) error {
			if d.IsDir() {
				return nil
			}
			pat := "GET /" + path
			mux.HandleFunc(pat, func(w http.ResponseWriter, r *http.Request) {
				http.ServeFileFS(w, r, static.FS, path)
			})
			return nil
		})
	} else {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "static/index.html")
		})
		filepath.WalkDir("static", func(path string, d fs.DirEntry, err error) error {
			if d.IsDir() {
				return nil
			}
			pat := "GET /" + strings.TrimPrefix(path, "static/")
			mux.HandleFunc(pat, func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, path)
			})
			return nil
		})
	}
	mux.HandleFunc("GET /app/signature", app.signature)
	mux.HandleFunc("GET /app/auth-callback", app.authCallback)

	_ = sentryhttp.
		New(sentryhttp.Options{
			WaitForDelivery: true,
			Timeout:         5 * time.Second,
			Repanic:         !app.isLambda(),
		}).
		Handle(mux)
	route := app.logRoute(mux)
	return route
}

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

func (app *appEnv) signature(w http.ResponseWriter, r *http.Request) {
	cl := app.googleClient(r, gmail.GmailSettingsBasicScope)
	if cl == nil {
		app.authRedirect(w, r)
		return
	}
	var listRes gmail.ListSendAsResponse
	err := requests.
		URL(`https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs?alt=json&prettyPrint=false`).
		Client(cl).
		ToJSON(&listRes).
		Fetch(r.Context())
	if err != nil {
		app.replyErr(w, r, err)
		return
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(&listRes)
}

func (app *appEnv) authRedirect(w http.ResponseWriter, r *http.Request) {
	app.setCookie(w, redirectURLCookie, r.URL)

	stateToken := rand.Text()
	app.setCookie(w, stateCookie, stateToken)

	conf := app.googleConfig(gmail.GmailSettingsBasicScope)
	// Redirect user to Google's consent page to ask for permission
	url := conf.AuthCodeURL(stateToken)
	w.Header().Set("Cache-Control", "no-cache")
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (app *appEnv) authCallback(w http.ResponseWriter, r *http.Request) {
	var state string
	if !app.getCookie(r, stateCookie, &state) {
		app.replyErr(w, r, resperr.New(http.StatusUnauthorized, "no saved state"))
		return
	}
	app.deleteCookie(w, stateCookie)

	var redirect url.URL
	if !app.getCookie(r, redirectURLCookie, &redirect) {
		app.replyErr(w, r, resperr.New(http.StatusUnauthorized, "no redirect"))
		return
	}
	app.deleteCookie(w, redirectURLCookie)

	if callbackState := r.FormValue("state"); state != callbackState {
		app.replyErr(w, r, resperr.New(
			http.StatusBadRequest,
			"token %q != %q",
			state, callbackState))
		return
	}
	conf := app.googleConfig(gmail.GmailSettingsBasicScope)
	tok, err := conf.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		app.replyErr(w, r, err)
		return
	}
	app.setCookie(w, tokenCookie, &tok)
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

package webapp

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/carlmjohnson/resperr"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/gorilla/schema"
	"github.com/spotlightpa/gmailsig/layouts"
	"github.com/spotlightpa/gmailsig/static"
	"google.golang.org/api/gmail/v1"
)

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
		fs.WalkDir(static.FS, ".", func(path string, d fs.DirEntry, err error) error {
			if d.IsDir() {
				return nil
			}
			pat := "GET /" + path
			mux.HandleFunc(pat, func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("static", path))
			})
			return nil
		})
	}
	mux.HandleFunc("GET /app/auth-callback", app.authCallback)
	mux.HandleFunc("GET /app/healthcheck", app.healthCheck)
	mux.HandleFunc("POST /app/logout", app.postLogout)
	mux.HandleFunc("GET /app/sentrycheck", app.sentryCheck)
	mux.HandleFunc("GET /app/signature", app.signaturePage)
	mux.HandleFunc("POST /app/signature", app.postSignature)

	// Middleware, inside out
	var route http.Handler = mux
	route = timeoutMiddleware(9*time.Second, route)
	route = versionMiddleware(route)
	const oneMB = 1 << 20
	route = http.MaxBytesHandler(route, oneMB)
	route = sentryhttp.
		New(sentryhttp.Options{
			WaitForDelivery: true,
			Timeout:         5 * time.Second,
			Repanic:         !app.isLambda(),
		}).
		Handle(route)
	route = app.logRoute(route)
	return route
}

func (app *appEnv) signaturePage(w http.ResponseWriter, r *http.Request) {
	cl := app.googleClient(r, gmail.GmailSettingsBasicScope)
	if cl == nil {
		app.authRedirect(w, r, gmail.GmailSettingsBasicScope)
		return
	}
	var listRes gmail.ListSendAsResponse
	err := requests.
		URL(`https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs?alt=json&prettyPrint=false`).
		Client(cl).
		ToJSON(&listRes).
		Fetch(r.Context())
	if err != nil {
		app.replyHTMLErr(w, r,
			resperr.WithCodeAndMessage(err, http.StatusBadGateway, "Bad response from Google"))
		return
	}

	var sig *gmail.SendAs
	for _, res := range listRes.SendAs {
		if res.IsPrimary {
			sig = res
			break
		}
	}
	if sig == nil {
		app.replyHTMLErr(w, r, errors.New("primary send-as alias not found for user"))
		return
	}
	var csrf string
	app.getCookie(r, csrfCookie, &csrf)
	app.replyHTML(w, r, layouts.SignaturePage, struct {
		Title, Email, Signature, CSRF string
	}{
		Title:     "Set Signature",
		Email:     sig.SendAsEmail,
		Signature: sig.Signature,
		CSRF:      csrf,
	})
}

func (app *appEnv) postLogout(w http.ResponseWriter, r *http.Request) {
	app.deleteCookie(w, tokenCookie)
	app.deleteCookie(w, stateCookie)
	app.deleteCookie(w, redirectURLCookie)
	app.deleteCookie(w, scopesCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *appEnv) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "OK")
}

func (app *appEnv) sentryCheck(w http.ResponseWriter, r *http.Request) {
	app.logErr(r.Context(), errors.New("sentry check"))
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "OK")
}

func (app *appEnv) postSignature(w http.ResponseWriter, r *http.Request) {
	cl := app.googleClient(r, gmail.GmailSettingsBasicScope)
	if cl == nil {
		app.authRedirect(w, r, gmail.GmailSettingsBasicScope)
		return
	}
	if err := r.ParseForm(); err != nil {
		app.replyHTMLErr(w, r, resperr.WithStatusCode(err, http.StatusBadRequest))
	}
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	var req struct {
		Email     string `schema:"email"`
		Signature string `schema:"signature"`
		CSRF      string `schema:"csrf"`
	}

	if err := decoder.Decode(&req, r.PostForm); err != nil {
		app.replyHTMLErr(w, r, resperr.WithStatusCode(err, http.StatusBadRequest))
		return
	}
	if !app.isCSRFOkay(r, req.CSRF) {
		err := fmt.Errorf("bad CSRF token: %q", req.CSRF)
		err = resperr.WithCodeAndMessage(err, http.StatusBadRequest, "Log in information is stale. Please log in again.")
		app.replyHTMLErr(w, r, err)
		return
	}

	update := gmail.SendAs{
		Signature: req.Signature,
	}
	var res gmail.SendAs
	err := requests.
		URL(`https://gmail.googleapis.com`).
		Pathf("/gmail/v1/users/me/settings/sendAs/%s", req.Email).
		Method(http.MethodPatch).
		Client(cl).
		BodyJSON(update).
		ToJSON(&res).
		Fetch(r.Context())
	if err != nil {
		app.replyHTMLErr(w, r,
			resperr.WithCodeAndMessage(err, http.StatusBadGateway, "Bad response from Google"))
		return
	}
	http.Redirect(w, r, "/app/signature", http.StatusSeeOther)
}

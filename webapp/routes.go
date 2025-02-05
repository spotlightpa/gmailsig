package webapp

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/carlmjohnson/resperr"
	sentryhttp "github.com/getsentry/sentry-go/http"
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

	route := sentryhttp.
		New(sentryhttp.Options{
			WaitForDelivery: true,
			Timeout:         5 * time.Second,
			Repanic:         !app.isLambda(),
		}).
		Handle(mux)
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
	app.replyHTML(w, r, layouts.SignaturePage, struct {
		Title, Email, Signature string
	}{
		Title:     "Set Signature",
		Email:     sig.SendAsEmail,
		Signature: sig.Signature,
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

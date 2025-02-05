package webapp

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"path/filepath"
	"time"

	"github.com/carlmjohnson/requests"
	sentryhttp "github.com/getsentry/sentry-go/http"
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
	mux.HandleFunc("GET /app/signature", app.signature)
	mux.HandleFunc("GET /app/auth-callback", app.authCallback)

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

func (app *appEnv) signature(w http.ResponseWriter, r *http.Request) {
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
		app.replyHTMLErr(w, r, err)
		return
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(&listRes)
}

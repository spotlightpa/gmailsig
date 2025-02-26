package webapp

import (
	"cmp"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/earthboundkid/resperr/v2"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/gorilla/schema"
	"github.com/spotlightpa/gmailsig/layouts"
	"github.com/spotlightpa/gmailsig/static"
	"google.golang.org/api/gmail/v1"
)

func (app *appEnv) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.notFound)
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
	mux.HandleFunc("GET /app/signature-preview", app.signaturePreview)
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

func (app *appEnv) notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write(static.FourOhFour)
}

var photoIDRe = regexp.MustCompile(`https://images.data.spotlightpa.org/insecure/[^.]+`)

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
			resperr.E{E: err, S: http.StatusBadGateway, M: "Bad response from Google"})
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
	var sigFields SigFields
	sigFields.Email = sig.SendAsEmail
	sigFields.Name = sig.DisplayName
	if match := photoIDRe.FindString(sig.Signature); match != "" {
		if i := strings.LastIndexByte(match, '/'); i >= 0 {
			b64 := match[i+1:]
			if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
				sigFields.PhotoID = string(decoded)
			}
		}
	}

	if err := r.ParseForm(); err != nil {
		app.replyHTMLErr(w, r, resperr.E{E: err, S: http.StatusBadRequest})
	}
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	if err := decoder.Decode(&sigFields, r.Form); err != nil {
		app.replyHTMLErr(w, r, resperr.E{E: err, S: http.StatusBadRequest})
		return
	}

	var csrf string
	app.getCookie(r, csrfCookie, &csrf)
	app.replyHTML(w, r, layouts.SignaturePage, struct {
		Title, Account, Signature, CSRF string
		SigFields
	}{
		Title:     "Set Signature",
		Account:   sig.SendAsEmail,
		Signature: sig.Signature,
		CSRF:      csrf,
		SigFields: sigFields,
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
		app.replyHTMLErr(w, r, resperr.E{E: err, S: http.StatusBadRequest})
	}
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	var req struct {
		Account string `schema:"account"`
		CSRF    string `schema:"csrf"`
		SigFields
	}

	if err := decoder.Decode(&req, r.PostForm); err != nil {
		app.replyHTMLErr(w, r, resperr.E{E: err, S: http.StatusBadRequest})
		return
	}
	if !app.isCSRFOkay(r, req.CSRF) {
		err := fmt.Errorf("bad CSRF token: %q", req.CSRF)
		err = resperr.E{E: err, S: http.StatusBadRequest, M: "Log in information is stale. Please log in again."}
		app.replyHTMLErr(w, r, err)
		return
	}

	req.SigFields.process()

	var sigBuff strings.Builder
	if err := layouts.SignatureBlock(&sigBuff, req.SigFields); err != nil {
		app.replyHTMLErr(w, r, err)
		return
	}

	update := gmail.SendAs{
		Signature: sigBuff.String(),
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
			resperr.E{E: err, S: http.StatusBadGateway, M: "Bad response from Google"})
		return
	}
	qs := make(url.Values)
	if err := schema.NewEncoder().Encode(req.SigFields, qs); err != nil {
		app.logErr(r.Context(), err)
		// fallthrough
	}
	http.Redirect(w, r, "/app/signature?"+qs.Encode(), http.StatusSeeOther)
}

type SigFields struct {
	Name            string `schema:"name"`
	Email           string `schema:"email"`
	PhotoID         string `schema:"photoid"`
	ProfileLink     string `schema:"profilelink"`
	ImageURL        string `schema:"-"`
	Role            string `schema:"role"`
	Pronouns        string `schema:"pronouns"`
	Twitter         string `schema:"twitter"`
	Bluesky         string `schema:"bluesky"`
	Telephone       string `schema:"telephone"`
	TelephoneDigits string `schema:"-"`
	Signal          string `schema:"signal"`
	SignalDigits    string `schema:"-"`
}

var notANumberRe = regexp.MustCompile(`\D`)

func (sf *SigFields) process() {
	if sf.PhotoID != "" && !strings.HasPrefix(sf.PhotoID, "http") {
		b64 := base64.StdEncoding.EncodeToString([]byte(sf.PhotoID))
		sf.ImageURL = fmt.Sprintf(`https://images.data.spotlightpa.org/insecure/rt:fill/w:210/h:210/g:ce/el:1/q:75/%s.jpeg`, b64)
	}
	sf.Twitter = strings.TrimPrefix(sf.Twitter, "@")
	sf.Twitter = strings.TrimPrefix(sf.Twitter, "https://twitter.com/")
	sf.Twitter = strings.TrimPrefix(sf.Twitter, "https://x.com/")
	sf.Bluesky = strings.TrimPrefix(sf.Bluesky, "@")
	sf.Bluesky = strings.TrimPrefix(sf.Bluesky, "https://bsky.app/profile/")

	sf.ImageURL = cmp.Or(sf.ImageURL, "https://files.data.spotlightpa.org/uploads/01kt/a0cx/user.png")
	sf.TelephoneDigits = notANumberRe.ReplaceAllString(sf.Telephone, "")
	sf.SignalDigits = notANumberRe.ReplaceAllString(sf.Signal, "")
}

func (app *appEnv) signaturePreview(w http.ResponseWriter, r *http.Request) {
	var data SigFields
	if err := r.ParseForm(); err != nil {
		app.replyHTMLErr(w, r, resperr.E{E: err, S: http.StatusBadRequest})
	}
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	if err := decoder.Decode(&data, r.Form); err != nil {
		app.replyHTMLErr(w, r, resperr.E{E: err, S: http.StatusBadRequest})
		return
	}
	data.process()

	app.replyHTML(w, r, layouts.SignaturePreview, &data)
}

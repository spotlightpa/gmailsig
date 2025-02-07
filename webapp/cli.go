package webapp

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/carlmjohnson/flagx"
	"github.com/carlmjohnson/gateway"
	"github.com/earthboundkid/versioninfo/v2"
	"github.com/spotlightpa/gmailsig/layouts"

	"github.com/getsentry/sentry-go"
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
	path := fl.String("template-dir", "", "`path` to use for local dev template reloading")
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
	logger.SetPrefix(AppName + " ")
	logger.SetFlags(log.LstdFlags | log.Lshortfile)
	app.signingSecret = []byte(*secret)
	if *secret == "" {
		logger.Println("WARNING: no signing-secret")
	}
	if *path != "" {
		layouts.UseLocalTemplates(*path, logger)
	}
	if err := app.initSentry(*sentryDSN); err != nil {
		return err
	}
	return nil
}

type appEnv struct {
	port              int
	oauthClientID     string
	oauthClientSecret string
	signingSecret     []byte
}

func (app *appEnv) Exec() (err error) {
	listener := gateway.ListenAndServe
	var portStr string
	if u, _ := url.Parse(os.Getenv("URL")); app.isLambda() && u != nil {
		portStr = u.Hostname()
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
		logger.Println("WARNING: no Sentry DSN")
		return nil
	}
	return sentry.Init(sentry.ClientOptions{
		Dsn:       dsn,
		Release:   versioninfo.Revision,
		Transport: transport,
		ServerName: os.Getenv("SITE_ID"),
	})
}

func (app *appEnv) isLambda() bool {
	return app.port == -1
}

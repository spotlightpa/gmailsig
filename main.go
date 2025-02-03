package main

import (
	"os"

	"github.com/carlmjohnson/exitcode"
	"github.com/spotlightpa/gmailsig/webapp"
)

func main() {
	exitcode.Exit(webapp.CLI(os.Args[1:]))
}

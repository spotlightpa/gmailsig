package layouts

import (
	"embed"
	"html/template"
	"io"
	"log"
	"path/filepath"
)

//go:embed *.html
var FS embed.FS

var path string

var logger *log.Logger

func UseLocalTemplates(templatedir string, l *log.Logger) {
	path = templatedir
	logger = l
}

func makeTemplate(names ...string) func(wr io.Writer, data any) error {
	baseName := names[0]
	t := template.Must(
		template.
			New(baseName).
			Funcs(nil).
			ParseFS(FS, names...))

	return func(wr io.Writer, data any) error {
		if path == "" {
			return t.Execute(wr, data)
		}
		logger.Printf("reparsing template %v", names)
		paths := make([]string, len(names))
		for i, name := range names {
			paths[i] = filepath.Join(path, name)
		}
		var err error
		t, err = template.
			New(baseName).
			Funcs(nil).
			ParseFiles(paths...)
		if err != nil {
			return err
		}
		return t.Execute(wr, data)
	}
}

var (
	Error          = makeTemplate("baseof.html", "error.html")
	SignaturePage  = makeTemplate("baseof.html", "signature-page.html")
	BuildSignature = makeTemplate("build-signature.html")
)

package static

import "embed"

//go:embed *.html *.ico *.css
var FS embed.FS

//go:embed 404.html
var FourOhFour []byte

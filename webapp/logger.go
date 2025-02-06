package webapp

import (
	"log"
	"net/http"
	"time"

	"github.com/carlmjohnson/requests"
)

var logger = log.Default()

var HTTPTransport http.RoundTripper

func init() {
	HTTPTransport = requests.LogTransport(http.DefaultTransport, logReq)
	http.DefaultTransport = HTTPTransport
}

func logReq(req *http.Request, res *http.Response, err error, duration time.Duration) {
	speedClass := "GOOD"
	if duration > 300*time.Millisecond {
		speedClass = "OKAY"
	}
	if duration > 1*time.Second {
		speedClass = "SLOW"
	}
	logger.Printf("req: \"%s %s\" res: %d duration: %s %v",
		req.Method, req.Host, res.StatusCode, speedClass, duration)

}

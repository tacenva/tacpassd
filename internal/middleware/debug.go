package middleware

import (
	"log"
	"net/http"
	"time"
)

type debugResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *debugResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *debugResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return w.ResponseWriter.Write(data)
}

func Debug(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf(
			"[HTTP] --> %s %s",
			r.Method,
			r.URL.RequestURI(),
		)

		rw := &debugResponseWriter{
			ResponseWriter: w,
		}

		next.ServeHTTP(rw, r)

		log.Printf(
			"[HTTP] <-- %s %s %d %s",
			r.Method,
			r.URL.RequestURI(),
			rw.status,
			time.Since(start),
		)
	})
}

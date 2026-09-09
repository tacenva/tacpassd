package middleware

import (
	"bytes"
	"log"
	"net/http"
	"time"
)

type debugResponseWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *debugResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}

	w.status = status

	w.ResponseWriter.WriteHeader(status)
}

func (w *debugResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	w.body.Write(data)

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

		status := rw.status

		if status == 0 {
			status = http.StatusOK
		}

		duration := time.Since(start)

		log.Printf(
			"[HTTP] <-- %s %s %d %s",
			r.Method,
			r.URL.RequestURI(),
			status,
			duration,
		)

		if status >= http.StatusBadRequest {
			body := rw.body.String()

			if body == "" {
				body = "<empty response>"
			}

			log.Printf(
				"[HTTP] ERROR %s %s: %s",
				r.Method,
				r.URL.RequestURI(),
				body,
			)
		}
	})
}

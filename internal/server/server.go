package server

import (
	"net/http"
	"time"
)

type Server struct {
	httpServer *http.Server
}

func New(
	addr string,
	handler http.Handler,
) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

func (s *Server) Run(
	certFile string,
	keyFile string,
) error {
	return s.httpServer.ListenAndServeTLS(
		certFile,
		keyFile,
	)
}

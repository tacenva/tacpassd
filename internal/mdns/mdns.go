package mdns

import (
	"fmt"

	"github.com/hashicorp/mdns"
)

type Server struct {
	server *mdns.Server
}

func Start(
	name string,
	port int,
) (*Server, error) {
	service, err := mdns.NewMDNSService(
		name,
		"_https._tcp",
		"local.",
		"",
		port,
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create mdns service: %w",
			err,
		)
	}

	server, err := mdns.NewServer(
		&mdns.Config{
			Zone: service,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"start mdns server: %w",
			err,
		)
	}

	return &Server{
		server: server,
	}, nil
}

func (s *Server) Shutdown() {
	if s == nil || s.server == nil {
		return
	}

	s.server.Shutdown()
}

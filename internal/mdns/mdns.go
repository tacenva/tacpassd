package mdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/mdns"
)

type Server struct {
	server *mdns.Server
}

func Start(
	name string,
	port int,
) (*Server, error) {
	name = normalizeHostname(name)

	if name == "" {
		return nil, fmt.Errorf(
			"hostname is required",
		)
	}

	iface, err := net.InterfaceByName("wlp2s0")
	if err != nil {
		return nil, fmt.Errorf(
			"find network interface: %w",
			err,
		)
	}

	ips, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf(
			"get interface addresses: %w",
			err,
		)
	}

	var serviceIPs []net.IP

	for _, addr := range ips {
		var ip net.IP

		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP

		case *net.IPAddr:
			ip = value.IP
		}

		if ip == nil || ip.IsLoopback() {
			continue
		}

		if !ip.IsPrivate() {
			continue
		}

		serviceIPs = append(
			serviceIPs,
			ip,
		)
	}

	if len(serviceIPs) == 0 {
		return nil, fmt.Errorf(
			"no usable IP address found on %s",
			iface.Name,
		)
	}

	service, err := mdns.NewMDNSService(
		strings.TrimSuffix(name, ".local"),
		"_https._tcp",
		"local.",
		name+".",
		port,
		serviceIPs,
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
			Zone:  service,
			Iface: iface,
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

func normalizeHostname(
	hostname string,
) string {
	hostname = strings.TrimSpace(hostname)
	hostname = strings.TrimSuffix(hostname, ".")

	if hostname == "" {
		return ""
	}

	if !strings.HasSuffix(
		strings.ToLower(hostname),
		".local",
	) {
		hostname += ".local"
	}

	return hostname
}

func (s *Server) Shutdown() {
	if s == nil || s.server == nil {
		return
	}

	_ = s.server.Shutdown()
}

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

func Start(name string, port int) (*Server, error) {
	name = normalizeHostname(name)

	if name == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	iface, err := findInterface()
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf(
			"get interface addresses: %w",
			err,
		)
	}

	serviceIPs := privateIPv4Addresses(addrs)

	if len(serviceIPs) == 0 {
		return nil, fmt.Errorf(
			"no usable private IPv4 address found on %s",
			iface.Name,
		)
	}

	txt := []string{
		"service=tacpassd",
		"version=1",
	}

	service, err := mdns.NewMDNSService(
		strings.TrimSuffix(name, ".local"),
		"_https._tcp",
		"local.",
		name+".",
		port,
		serviceIPs,
		txt,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create mdns service: %w",
			err,
		)
	}

	server, err := mdns.NewServer(&mdns.Config{
		Zone:              service,
		Iface:             iface,
		LogEmptyResponses: true,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"start mdns server: %w",
			err,
		)
	}

	fmt.Printf(
		"mDNS server listening on %s (%s)\n",
		iface.Name,
		strings.Join(ipStrings(serviceIPs), ", "),
	)

	return &Server{
		server: server,
	}, nil
}

func findInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf(
			"list network interfaces: %w",
			err,
		)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		if isVirtualInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		if !hasPrivateIPv4(addrs) {
			continue
		}

		return &iface, nil
	}

	return nil, fmt.Errorf(
		"no suitable multicast interface found",
	)
}

func isVirtualInterface(name string) bool {
	prefixes := []string{
		"docker",
		"br-",
		"veth",
		"vmnet",
		"virbr",
		"lxc",
		"cni",
		"flannel",
		"tun",
		"tap",
	}

	name = strings.ToLower(name)

	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

func hasPrivateIPv4(addrs []net.Addr) bool {
	for _, addr := range addrs {
		ip := addressIP(addr)

		if ip == nil {
			continue
		}

		ip = ip.To4()

		if ip == nil {
			continue
		}

		if ip.IsLoopback() {
			continue
		}

		if ip.IsPrivate() {
			return true
		}
	}

	return false
}

func privateIPv4Addresses(addrs []net.Addr) []net.IP {
	var result []net.IP

	for _, addr := range addrs {
		ip := addressIP(addr)

		if ip == nil {
			continue
		}

		ip = ip.To4()

		if ip == nil {
			continue
		}

		if ip.IsLoopback() {
			continue
		}

		if !ip.IsPrivate() {
			continue
		}

		result = append(result, ip)
	}

	return result
}

func addressIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP

	case *net.IPAddr:
		return value.IP

	default:
		return nil
	}
}

func ipStrings(ips []net.IP) []string {
	result := make([]string, 0, len(ips))

	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result
}

func normalizeHostname(hostname string) string {
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

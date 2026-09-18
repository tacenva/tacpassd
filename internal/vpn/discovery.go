package vpn

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
)

const (
	DiscoveryPort = 49154

	Magic   = "tacpassd-vpn-discovery"
	Version = 1
)

type Request struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
}

type Response struct {
	Magic    string `json:"magic"`
	Version  int    `json:"version"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

type Server struct {
	conn     *net.UDPConn
	Hostname string
	Port     int
}

func Start(
	interfaceName string,
	hostname string,
	httpsPort int,
) (*Server, error) {
	if strings.TrimSpace(interfaceName) == "" {
		return nil, fmt.Errorf("VPN interface name is required")
	}

	if strings.TrimSpace(hostname) == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	if httpsPort <= 0 || httpsPort > 65535 {
		return nil, fmt.Errorf("invalid HTTPS port: %d", httpsPort)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf(
			"find VPN interface %s: %w",
			interfaceName,
			err,
		)
	}

	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf(
			"VPN interface %s is down",
			interfaceName,
		)
	}

	ip, err := interfaceIPv4(iface)
	if err != nil {
		return nil, err
	}

	addr := &net.UDPAddr{
		IP:   ip,
		Port: DiscoveryPort,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf(
			"listen VPN discovery on %s: %w",
			addr,
			err,
		)
	}

	server := &Server{
		conn:     conn,
		Hostname: normalizeHostname(hostname),
		Port:     httpsPort,
	}

	go server.loop()

	log.Printf(
		"VPN discovery started on %s:%d",
		ip,
		DiscoveryPort,
	)

	return server, nil
}

func (s *Server) loop() {
	buffer := make([]byte, 4096)

	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		request, err := decodeRequest(buffer[:n])
		if err != nil {
			log.Printf(
				"VPN discovery invalid request from %s: %v",
				remoteAddr,
				err,
			)
			continue
		}

		if request.Magic != Magic {
			continue
		}

		response, err := json.Marshal(Response{
			Magic:    Magic,
			Version:  Version,
			Hostname: s.Hostname,
			Port:     s.Port,
		})
		if err != nil {
			log.Printf(
				"VPN discovery encode response: %v",
				err,
			)
			continue
		}

		if _, err := s.conn.WriteToUDP(response, remoteAddr); err != nil {
			log.Printf(
				"VPN discovery response to %s: %v",
				remoteAddr,
				err,
			)
		}
	}
}

func (s *Server) Shutdown() {
	if s == nil || s.conn == nil {
		return
	}

	_ = s.conn.Close()
}

func interfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf(
			"get addresses for %s: %w",
			iface.Name,
			err,
		)
	}

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

		return ip, nil
	}

	return nil, fmt.Errorf(
		"no IPv4 address found on %s",
		iface.Name,
	)
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

func decodeRequest(data []byte) (Request, error) {
	var request Request

	if err := json.Unmarshal(data, &request); err != nil {
		return Request{}, fmt.Errorf(
			"decode request: %w",
			err,
		)
	}

	if request.Magic != Magic {
		return Request{}, fmt.Errorf(
			"invalid magic %q",
			request.Magic,
		)
	}

	if request.Version != Version {
		return Request{}, fmt.Errorf(
			"unsupported protocol version %d",
			request.Version,
		)
	}

	return request, nil
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

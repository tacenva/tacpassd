package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func GenerateSelfSignedCert(certFile, keyFile string) error {
	if certFile == "" {
		return fmt.Errorf("cert file is required")
	}

	if keyFile == "" {
		return fmt.Errorf("key file is required")
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(
		rand.Reader,
		serialLimit,
	)
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	privateIPs, err := getPrivateIPs()
	if err != nil {
		return fmt.Errorf("get private ips: %w", err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,

		Subject: pkix.Name{
			CommonName: "tacpassd",
		},

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.AddDate(1, 0, 0),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,

		DNSNames: []string{
			"localhost",
		},

		IPAddresses: append(
			[]net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("::1"),
			},
			privateIPs...,
		),
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.OpenFile(
		certFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0644,
	)
	if err != nil {
		return fmt.Errorf("create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(
		certOut,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		},
	); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	keyOut, err := os.OpenFile(
		keyFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(
		keyOut,
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		},
	); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}

func getPrivateIPs() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var privateIPs []net.IP

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}

			if ip == nil || !ip.IsPrivate() {
				continue
			}

			key := ip.String()

			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}
			privateIPs = append(privateIPs, ip)
		}
	}

	return privateIPs, nil
}

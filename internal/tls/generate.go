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
	"strings"
	"time"
)

func GenerateSelfSignedCert(
	certFile string,
	keyFile string,
	hostname string,
) error {
	if certFile == "" {
		return fmt.Errorf("cert file is required")
	}

	if keyFile == "" {
		return fmt.Errorf("key file is required")
	}

	hostname = normalizeHostname(hostname)

	if hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	// Both already exist.
	//
	// Keep the existing private key and certificate when they are
	// still valid for the configured hostname.
	if fileExists(certFile) && fileExists(keyFile) {
		valid, err := certificateIsValid(
			certFile,
			keyFile,
			hostname,
		)
		if err != nil {
			return fmt.Errorf(
				"check existing certificate: %w",
				err,
			)
		}

		if valid {
			return nil
		}

		// Certificate needs to be updated, but keep the
		// existing private key so the server identity does
		// not change.
		privateKey, err := loadPrivateKey(keyFile)
		if err != nil {
			return fmt.Errorf(
				"load existing private key: %w",
				err,
			)
		}

		return writeCertificate(
			certFile,
			privateKey,
			hostname,
		)
	}

	// A key exists but the certificate does not.
	//
	// Reuse the existing key instead of generating another one.
	if fileExists(keyFile) {
		privateKey, err := loadPrivateKey(keyFile)
		if err != nil {
			return fmt.Errorf(
				"load existing private key: %w",
				err,
			)
		}

		return writeCertificate(
			certFile,
			privateKey,
			hostname,
		)
	}

	// No private key exists, so this is a completely new
	// server identity.
	if err := os.MkdirAll(
		filepath.Dir(keyFile),
		0700,
	); err != nil {
		return fmt.Errorf(
			"create key directory: %w",
			err,
		)
	}

	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		return fmt.Errorf(
			"generate private key: %w",
			err,
		)
	}

	if err := writePrivateKey(
		keyFile,
		privateKey,
	); err != nil {
		return err
	}

	return writeCertificate(
		certFile,
		privateKey,
		hostname,
	)
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

func certificateIsValid(
	certFile string,
	keyFile string,
	hostname string,
) (bool, error) {
	certificate, err := loadCertificate(certFile)
	if err != nil {
		return false, err
	}

	privateKey, err := loadPrivateKey(keyFile)
	if err != nil {
		return false, err
	}

	// Make sure the certificate actually belongs to the
	// existing private key.
	certificatePublicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, nil
	}

	if certificatePublicKey.N.Cmp(privateKey.N) != 0 ||
		certificatePublicKey.E != privateKey.E {
		return false, nil
	}

	// Do not keep an expired certificate.
	now := time.Now()

	if now.Before(certificate.NotBefore) ||
		now.After(certificate.NotAfter) {
		return false, nil
	}

	// Modern TLS hostname verification uses SAN.
	for _, name := range certificate.DNSNames {
		if strings.EqualFold(name, hostname) {
			return true, nil
		}
	}

	return false, nil
}

func loadCertificate(
	certFile string,
) (*x509.Certificate, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf(
			"invalid certificate PEM",
		)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf(
			"unexpected PEM type %q",
			block.Type,
		)
	}

	certificate, err := x509.ParseCertificate(
		block.Bytes,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse certificate: %w",
			err,
		)
	}

	return certificate, nil
}

func loadPrivateKey(
	keyFile string,
) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf(
			"invalid private key PEM",
		)
	}

	var privateKey *rsa.PrivateKey

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(
			block.Bytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"parse PKCS#8 private key: %w",
				err,
			)
		}

		var ok bool

		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf(
				"private key is not RSA",
			)
		}

	case "RSA PRIVATE KEY":
		var err error

		privateKey, err = x509.ParsePKCS1PrivateKey(
			block.Bytes,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"parse PKCS#1 private key: %w",
				err,
			)
		}

	default:
		return nil, fmt.Errorf(
			"unsupported private key PEM type %q",
			block.Type,
		)
	}

	return privateKey, nil
}

func writePrivateKey(
	keyFile string,
	privateKey *rsa.PrivateKey,
) error {
	if err := os.MkdirAll(
		filepath.Dir(keyFile),
		0700,
	); err != nil {
		return fmt.Errorf(
			"create key directory: %w",
			err,
		)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(
		privateKey,
	)
	if err != nil {
		return fmt.Errorf(
			"marshal private key: %w",
			err,
		)
	}

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.WriteFile(
		keyFile,
		data,
		0600,
	); err != nil {
		return fmt.Errorf(
			"write private key: %w",
			err,
		)
	}

	return nil
}

func writeCertificate(
	certFile string,
	privateKey *rsa.PrivateKey,
	hostname string,
) error {
	if err := os.MkdirAll(
		filepath.Dir(certFile),
		0700,
	); err != nil {
		return fmt.Errorf(
			"create cert directory: %w",
			err,
		)
	}

	serialLimit := new(big.Int).Lsh(
		big.NewInt(1),
		128,
	)

	serialNumber, err := rand.Int(
		rand.Reader,
		serialLimit,
	)
	if err != nil {
		return fmt.Errorf(
			"generate serial number: %w",
			err,
		)
	}

	privateIPs, err := getPrivateIPs()
	if err != nil {
		return fmt.Errorf(
			"get private IPs: %w",
			err,
		)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,

		Subject: pkix.Name{
			CommonName: hostname,
		},

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.AddDate(1, 0, 0),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,

		// This is the important part for:
		//
		// https://archpc.local:49153
		//
		// Modern TLS clients validate the hostname
		// against SAN, not CommonName.
		DNSNames: []string{
			hostname,
		},

		IPAddresses: privateIPs,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return fmt.Errorf(
			"create certificate: %w",
			err,
		)
	}

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(
		certFile,
		data,
		0600,
	); err != nil {
		return fmt.Errorf(
			"write certificate: %w",
			err,
		)
	}

	return nil
}

func getPrivateIPs() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var privateIPs []net.IP

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if iface.Name == "docker0" ||
			iface.Name == "docker_gwbridge" ||
			strings.HasPrefix(iface.Name, "br-") ||
			strings.HasPrefix(iface.Name, "veth") {
			continue
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addresses {
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

			privateIPs = append(
				privateIPs,
				ip,
			)
		}
	}

	return privateIPs, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	rsaBits = 2048
)

func GenCACert(
	commonName, organizationName, countryCode string, validYears int,
	keyFileName, cerFileName string,
) (*rsa.PrivateKey, *x509.Certificate, error) {

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(validYears, 0, 0)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	cer := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organizationName},
			Country:      []string{countryCode},
		},
		Issuer: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organizationName},
			Country:      []string{countryCode},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	cerB, err := x509.CreateCertificate(rand.Reader, cer, cer, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cerF, err := os.Create(cerFileName)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(cerF, &pem.Block{Type: "CERTIFICATE", Bytes: cerB})
	if err != nil {
		return nil, nil, err
	}
	cerF.Close()

	keyF, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(keyF, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return nil, nil, err
	}
	keyF.Close()

	cer, err = x509.ParseCertificate(cerB)
	if err != nil {
		return nil, nil, err
	}

	return priv, cer, nil
}

func GenCert(
	hostName, commonName, organizationName, countryCode string, validDays int,
	caPriv *rsa.PrivateKey, caCer *x509.Certificate,
	keyFileName, cerFileName string,
) (*rsa.PrivateKey, *x509.Certificate, error) {

	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validDays)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	cer := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organizationName},
			Country:      []string{countryCode},
		},

		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: false,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	for _, h := range []string{hostName} {
		if ip := net.ParseIP(h); ip != nil {
			cer.IPAddresses = append(cer.IPAddresses, ip)
		} else {
			cer.DNSNames = append(cer.DNSNames, h)
		}
	}

	cerB, err := x509.CreateCertificate(rand.Reader, cer, caCer, &priv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	cerF, err := os.Create(cerFileName)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(cerF, &pem.Block{Type: "CERTIFICATE", Bytes: cerB})
	if err != nil {
		return nil, nil, err
	}
	cerF.Close()

	keyF, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(keyF, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return nil, nil, err
	}
	keyF.Close()

	cer, err = x509.ParseCertificate(cerB)
	if err != nil {
		return nil, nil, err
	}

	return priv, cer, nil
}

func LoadKey(keyFileName string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}

func LoadCert(cerFileName string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(cerFileName)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	return x509.ParseCertificate(blk.Bytes)
}

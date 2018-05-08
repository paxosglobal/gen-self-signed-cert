package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	keyBits = 2048
)

var (
	host    = flag.String("host", "", "the DNS name to create a cert for")
	outDir  = flag.String("out", ".", "the directory to write cert files")
	encrypt = flag.Bool("encrypt", false, "prompt for password and encrypt private key")
)

func main() {
	flag.Parse()
	if *host == "" {
		log.Fatal("-host flag is required")
	}
	password := ""
	if *encrypt {
		fmt.Println("-encrypt set, will AES-256 encrypt private key with provided password")
		fmt.Print("Enter password: ")
		passwordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("failed to read password: %s", err)
		}
		fmt.Println()
		password = string(passwordBytes)
		if password == "" {
			log.Fatalf("non-empty password must be set for encryption")
		}
	}
	err := generateCerts(*host, *outDir, password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("CA cert and host certificate generated!")
	fmt.Printf("CA certificate file:    %s\n",
		filepath.Join(*outDir, "ca.crt"))
	fmt.Printf("Host certificate file:  %s\n",
		filepath.Join(*outDir, "host.crt"))
	fmt.Printf("Host key file:          %s\n",
		filepath.Join(*outDir, "host.key"))
}

func generateCerts(host, outDir, keyPass string) error {
	caCert, err := createCertificate(host, nil)
	if err != nil {
		return fmt.Errorf("error creating CA cert: %s", err)
	}
	hostCert, err := createCertificate(host, caCert)
	if err != nil {
		return fmt.Errorf("error creating host cert: %s", err)
	}
	if err := writeCertPem(outDir, "ca", caCert); err != nil {
		return fmt.Errorf("error writing CA cert: %s", err)
	}
	if err := writeCertPem(outDir, "host", hostCert); err != nil {
		return fmt.Errorf("error writing host cert: %s", err)
	}
	if err := writeKeyPem(outDir, "host", hostCert, keyPass); err != nil {
		return fmt.Errorf("error writing host plaintextKey: %s", err)
	}
	return nil
}

type certData struct {
	cert       *x509.Certificate
	certBytes  []byte
	privateKey *rsa.PrivateKey
}

func writeKeyPem(dir, basename string, data *certData, password string) (err error) {
	bytes := x509.MarshalPKCS1PrivateKey(data.privateKey)
	var pemBlock *pem.Block
	if password != "" {
		pemBlock, err = x509.EncryptPEMBlock(
			rand.Reader,
			"RSA PRIVATE KEY",
			bytes,
			[]byte(password),
			x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	} else {
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: bytes}
	}

	file := filepath.Join(dir, basename+".key")

	// TODO: Permissions on key file.
	writer, err := os.Create(file)
	if err != nil {
		return err
	}
	err = pem.Encode(writer, pemBlock)
	if err != nil {
		return err
	}
	return writer.Close()
}

func writeCertPem(dir, basename string, data *certData) error {
	file := filepath.Join(dir, basename+".crt")
	writer, err := os.Create(file)
	if err != nil {
		return err
	}
	err = pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: data.certBytes})
	if err != nil {
		return err
	}
	return writer.Close()
}

func createCertificate(host string, parent *certData) (*certData, error) {
	var err error
	certTemplate := &x509.Certificate{
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
	}

	certTemplate.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private plaintextKey: %s", err)
	}
	marshaledKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pulic plaintextKey: %s", err)
	}
	subjectKeyID := sha1.Sum(marshaledKey)
	certTemplate.SubjectKeyId = subjectKeyID[:]

	var signingKey *rsa.PrivateKey
	var parentCert *x509.Certificate
	if parent == nil {
		certTemplate.IsCA = true
		// The CA is valid for 10 years and a day, to ensure it is valid longer than leaf.
		certTemplate.NotAfter = certTemplate.NotBefore.AddDate(10, 0, 1)
		certTemplate.KeyUsage |= x509.KeyUsageCertSign
		certTemplate.Subject = pkix.Name{
			CommonName: fmt.Sprintf("CA for %s", host),
		}
		certTemplate.AuthorityKeyId = certTemplate.SubjectKeyId
		signingKey = privateKey
		parentCert = certTemplate
	} else {
		// Valid for 10 years.
		certTemplate.NotAfter = certTemplate.NotBefore.AddDate(10, 0, 0)
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
		certTemplate.Subject = pkix.Name{
			CommonName: host,
		}
		certTemplate.DNSNames = []string{host}
		signingKey = parent.privateKey
		parentCert = parent.cert
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, parentCert, privateKey.Public(), signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err)
	}
	return &certData{
		cert:       cert,
		certBytes:  certBytes,
		privateKey: privateKey,
	}, nil
}

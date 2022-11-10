package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func writePEMFile(destFilePath string, blockType string, contentBuffer []byte) (err error) {
	blk := pem.Block{
		Type:  blockType,
		Bytes: contentBuffer,
	}
	fp, err := os.Create(destFilePath)
	if nil != err {
		log.Printf("ERROR: cannot open %s file for writing [%s]: %v", blockType, destFilePath, err)
		return
	}
	defer fp.Close()
	if err = pem.Encode(fp, &blk); nil != err {
		log.Printf("ERROR: cannot pack %s PEM info file: %v", blockType, err)
		return
	}
	return
}

func createPrivateKey(keyPath string, keySize int, keyPKCS1 bool) (privKey *rsa.PrivateKey, err error) {
	if privKey, err = rsa.GenerateKey(rand.Reader, keySize); nil != err {
		log.Printf("ERROR: cannot generate private key: %v", err)
		return
	}
	if keyPKCS1 {
		buf := x509.MarshalPKCS1PrivateKey(privKey)
		err = writePEMFile(keyPath, "RSA PRIVATE KEY", buf)
	} else {
		var buf []byte
		if buf, err = x509.MarshalPKCS8PrivateKey(privKey); nil != err {
			log.Printf("ERROR: cannot marshal provate key into PKCS#8 DER form: %v", err)
			return
		}
		err = writePEMFile(keyPath, "PRIVATE KEY", buf)
	}
	return
}

func createCertificateRequest(certReqPath string, subjectName *pkix.Name, certDNSNames []string, privKey *rsa.PrivateKey) (err error) {
	csrBuf, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  *subjectName,
		DNSNames: certDNSNames,
	}, privKey)
	if nil != err {
		log.Printf("ERROR: cannot generate certificate request: %v", err)
		return
	}
	err = writePEMFile(certReqPath, "CERTIFICATE REQUEST", csrBuf)
	return
}

func createSelfSignedCertificate(selfSignCertPath string, subjectName *pkix.Name, certDNSNames []string, selfSignedCertValidDuration time.Duration, privKey *rsa.PrivateKey) (err error) {
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      *subjectName,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(selfSignedCertValidDuration),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     certDNSNames,
	}
	cerBuf, err := x509.CreateCertificate(rand.Reader, certTpl, certTpl, &privKey.PublicKey, privKey)
	if nil != err {
		log.Printf("ERROR: cannot generate self-signed certificate: %v", err)
		return
	}
	err = writePEMFile(selfSignCertPath, "CERTIFICATE", cerBuf)
	return
}

func main() {
	keySize, subjectName, certDNSNames, keyPKCS1, selfSignedCertValidDuration, keyPath, certReqPath, selfSignCertPath, err := parseCommandParameter()
	if nil != err {
		log.Fatalf("cannot have valid command options: %v", err)
		return
	}
	privKey, err := createPrivateKey(keyPath, keySize, keyPKCS1)
	if nil != err {
		log.Fatalf("ERROR: failed on setting up private key: %v", err)
		return
	}
	log.Printf("INFO: generated private key: [%s]", keyPath)
	if certReqPath != "" {
		if err = createCertificateRequest(certReqPath, &subjectName, certDNSNames, privKey); nil != err {
			log.Fatalf("ERROR: failed on setting up certificate request: %v", err)
			return
		}
		log.Printf("INFO: generated certificate request: [%s]", certReqPath)
	} else {
		log.Print("INFO: skip certificate request generation.")
	}
	if selfSignCertPath != "" {
		if err = createSelfSignedCertificate(selfSignCertPath, &subjectName, certDNSNames, selfSignedCertValidDuration, privKey); nil != err {
			log.Fatalf("ERROR: failed on setting up self-signed certificate: %v", err)
			return
		}
		log.Printf("INFO: generated self-signed certificate: [%s]", selfSignCertPath)
	} else {
		log.Print("INFO: skip self-signed certificate generation.")
	}
}

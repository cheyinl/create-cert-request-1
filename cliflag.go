package main

import (
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultKeySize = 2048

type stringSlice []string

func (a *stringSlice) Set(v string) (err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	*a = append(([]string)(*a), v)
	return
}

func (a *stringSlice) String() string {
	aux := ([]string)(*a)
	if len(aux) == 0 {
		return "[]"
	}
	buf, err := json.Marshal(aux)
	if nil != err {
		return "<ERR:" + err.Error() + ">"
	}
	return string(buf)
}

func prepareFilePath(usageText, targetPath string, overwriteExisted bool) (absTargetPath string, err error) {
	if absTargetPath, err = filepath.Abs(targetPath); nil != err {
		log.Printf("ERROR: cannot have absolute representation of given %s path [%s]: %v", usageText, targetPath, err)
		return
	}
	if _, err = os.Stat(absTargetPath); nil == err {
		if overwriteExisted {
			log.Printf("WARN: file existed at given %s path: %s", usageText, absTargetPath)
		} else {
			log.Printf("ERROR: file existed at given %s path: %s", usageText, absTargetPath)
			err = errors.New("file existed: [" + absTargetPath + "]")
			return
		}
	} else if os.IsNotExist(err) {
		err = nil
	} else {
		log.Printf("ERROR: cannot check existence of given %s path [%s]: %v", usageText, absTargetPath, err)
		return
	}
	return
}

var errRequireKeyPath = errors.New("path of private key is required")

func parseCommandParameter() (
	keySize int,
	subjectName pkix.Name,
	certDNSNames []string,
	keyPKCS1 bool,
	selfSignedCertValidDuration time.Duration,
	keyPath, certReqPath, selfSignCertPath string,
	err error) {
	var dnCountry, dnOrganization, dnOrganizationalUnit, dnLocality, dnProvince stringSlice
	var dnCommonName string
	var dnsNames stringSlice
	var selfSignedCertValidDays int
	var overwriteExisted bool
	flag.IntVar(&keySize, "keySize", defaultKeySize, "key size in bits")
	flag.Var(&dnCountry, "C", "country name of certificate subject DN")
	flag.Var(&dnOrganization, "O", "organization of certificate subject DN")
	flag.Var(&dnOrganizationalUnit, "OU", "organizational unit of certificate subject DN")
	flag.Var(&dnLocality, "L", "locality of certificate subject DN")
	flag.Var(&dnProvince, "ST", "state or province name of certificate subject DN")
	flag.StringVar(&dnCommonName, "CN", "", "common name f certificate subject DN")
	flag.Var(&dnsNames, "dnsName", "DNS names of certificate (*Required*)")
	flag.BoolVar(&keyPKCS1, "pkcs1", false, "write private key in PKCS#1 format")
	flag.IntVar(&selfSignedCertValidDays, "selfSignValidDays", 366, "valid days of self signed certificate")
	flag.StringVar(&keyPath, "key", "cert-key.pem", "path of private key (*Required*)")
	flag.StringVar(&certReqPath, "req", "cert-req.pem", "path of certificate request")
	flag.StringVar(&selfSignCertPath, "selfSign", "cert-selfsigned.pem", "path of self-signed certificate")
	flag.BoolVar(&overwriteExisted, "overwrite", false, "overwrite existed files")
	flag.Parse()
	if keyPath == "" {
		err = errRequireKeyPath
		return
	}
	if keyPath, err = prepareFilePath("private key", keyPath, overwriteExisted); nil != err {
		return
	}
	if certReqPath != "" {
		if certReqPath, err = prepareFilePath("certificate request", certReqPath, overwriteExisted); nil != err {
			return
		}
	}
	if selfSignCertPath != "" {
		if selfSignCertPath, err = prepareFilePath("self-signed certificate", selfSignCertPath, overwriteExisted); nil != err {
			return
		}
	}
	if (dnCommonName == "") && (len(dnsNames) > 0) {
		dnCommonName = dnsNames[0]
	}
	subjectName = pkix.Name{
		Country:            dnCountry,
		Organization:       dnOrganization,
		OrganizationalUnit: dnOrganizationalUnit,
		Locality:           dnLocality,
		Province:           dnProvince,
		CommonName:         dnCommonName,
	}
	certDNSNames = dnsNames
	selfSignedCertValidDuration = time.Hour * 24 * time.Duration(selfSignedCertValidDays)
	return
}

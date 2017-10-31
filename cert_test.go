package cert_test

import (
	"fmt"

	"github.com/gopyai/cert"
)

func Example1() {
	createNewCACertificate()
	createNewHostCertificate()
	verifyHostCertificate()

	//Output:
	//CA certificate created
	//Host certificate created
	//Host certificate verified
}

func Example2() {
	caPriv, caCer, err := cert.GenCACert(
		"Vostra",
		"PT. Vostra Internasional",
		"ID",
		10,
		"ca.key",
		"ca.cer")
	isErr(err)
	fmt.Println("CA certificate created")

	_, hostCer, err := cert.GenCert(
		"localhost",
		"com.testing",
		"PT Testing Tbk",
		"ID",
		1,
		caPriv, caCer,
		"host.key",
		"host.cer")
	isErr(err)
	fmt.Println("Host certificate created")

	isErr(hostCer.CheckSignatureFrom(caCer))
	fmt.Println("Host certificate verified")

	//Output:
	//CA certificate created
	//Host certificate created
	//Host certificate verified
}

func createNewCACertificate() {
	_, _, err := cert.GenCACert(
		"Vostra",
		"PT. Vostra Internasional",
		"ID",
		10,
		"ca.key",
		"ca.cer")
	isErr(err)
	fmt.Println("CA certificate created")
}

func createNewHostCertificate() {
	caPriv, err := cert.LoadKey("ca.key")
	isErr(err)
	caCer, err := cert.LoadCert("ca.cer")
	isErr(err)
	_, _, err = cert.GenCert(
		"localhost",
		"com.testing",
		"PT Testing Tbk",
		"ID",
		1,
		caPriv, caCer,
		"host.key",
		"host.cer")
	isErr(err)
	fmt.Println("Host certificate created")
}

func verifyHostCertificate() {
	caCer, err := cert.LoadCert("ca.cer")
	isErr(err)
	hostCer, err := cert.LoadCert("host.cer")
	isErr(err)
	isErr(hostCer.CheckSignatureFrom(caCer))
	fmt.Println("Host certificate verified")
}

func isErr(e error) {
	if e != nil {
		panic(e)
	}
}

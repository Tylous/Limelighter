package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	crand "math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
)

type flagOptions struct {
	outFile   string
	inputFile string
	domain    string
	password  string
	real      string
	verify    string
}

var (
	debugging   bool
	debugWriter io.Writer
)

func printDebug(format string, v ...interface{}) {
	if debugging {
		output := fmt.Sprintf("[DEBUG] ")
		output += format
		fmt.Fprintf(debugWriter, output, v...)
	}
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func varNumberLength(min, max int) string {
	var r string
	crand.Seed(time.Now().UnixNano())
	num := crand.Intn(max-min) + min
	n := num
	r = randStringBytes(n)
	return r
}
func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[crand.Intn(len(letters))]

	}
	return string(b)
}

func generateCert(domain string, inputFile string) {
	var err error
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	certs, err := getCertificatesPEM(domain + ":443")
	if err != nil {
		os.Chdir("..")
		foldername := strings.Split(inputFile, ".")
		os.RemoveAll(foldername[0])
		log.Fatal("Error: The domain: " + domain + " does not exist or is not accessible from the host you are compiling on")
	}
	block, _ := pem.Decode([]byte(certs))
	cert, _ := x509.ParseCertificate(block.Bytes)

	keyToFile(domain+".key", rootKey)

	subjectTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Subject.CommonName,
		},
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		BasicConstraintsValid: true,
		IsCA:        true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	issuerTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Issuer.CommonName,
		},
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &subjectTemplate, &issuerTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	certToFile(domain+".pem", derBytes)

}

func keyToFile(filename string, key *rsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal RSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("[-] Failed to Open cert.pem for Writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("[-] Failed to Write Data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("[-] Error Closing cert.pem: %s", err)
	}
}

func getCertificatesPEM(address string) (string, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func generatePFK(password string, domain string) {
	cmd := exec.Command("openssl", "pkcs12", "-export", "-out", domain+".pfx", "-inkey", domain+".key", "-in", domain+".pem", "-passin", "pass:"+password+"", "-passout", "pass:"+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func signExecutable(password string, pfx string, filein string, fileout string) {
	cmd := exec.Command("osslsigncode", "sign", "-pkcs12", pfx, "-in", ""+filein+"", "-out", ""+fileout+"", "-pass", ""+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func check(check string) {

	cmd := exec.Command("osslsigncode", "verify", ""+check+"")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func options() *flagOptions {
	outFile := flag.String("O", "", "Signed file name")
	inputFile := flag.String("I", "", "Unsiged file name to be signed")
	domain := flag.String("Domain", "", "Domain you want to create a fake code sign for")
	password := flag.String("Password", "", "Password for real certificate")
	real := flag.String("Real", "", "Path to a valid .pfx certificate file")
	verify := flag.String("Verify", "", "Verifies a file's code sign certificate")
	debug := flag.Bool("debug", false, "Print debug statements")
	flag.Parse()
	debugging = *debug
	debugWriter = os.Stdout
	return &flagOptions{outFile: *outFile, inputFile: *inputFile, domain: *domain, password: *password, real: *real, verify: *verify}
}

func main() {
	fmt.Println(`
	.____    .__               .____    .__       .__     __                
	|    |   |__| _____   ____ |    |   |__| ____ |  |___/  |_  ___________ 
	|    |   |  |/     \_/ __ \|    |   |  |/ ___\|  |  \   __\/ __ \_  __ \
	|    |___|  |  Y Y  \  ___/|    |___|  / /_/  >   Y  \  | \  ___/|  | \/
	|_______ \__|__|_|  /\___  >_______ \__\___  /|___|  /__|  \___  >__|   
		\/        \/     \/        \/ /_____/      \/          \/         			
							@Tyl0us
	
	
[*] A Tool for Code Signing... Real and fake`)
	opt := options()
	if opt.verify == "" && opt.inputFile == "" && opt.outFile == "" {
		log.Fatal("Error: Please provide a file to sign or a file check")
	}

	if opt.verify == "" && opt.inputFile == "" {
		log.Fatal("Error: Please provide a file to sign")
	}
	if opt.verify == "" && opt.outFile == "" {
		log.Fatal("Error: Please provide a name for the signed file")
	}
	if opt.real == "" && opt.domain == "" && opt.verify == "" {
		log.Fatal("Error: Please specify a valid path to a .pfx file or specify the domain to spoof")
	}

	if opt.verify != "" {
		fmt.Println("[*] Checking code signed on file: " + opt.verify)
		check(opt.verify)
		os.Exit(3)
	}

	if opt.real != "" {
		fmt.Println("[*] Signing " + opt.inputFile + " with a valid cert " + opt.real)
		signExecutable(opt.password, opt.real, opt.inputFile, opt.outFile)

	} else {
		password := varNumberLength(8, 12)
		pfx := opt.domain + ".pfx"
		fmt.Println("[*] Signing " + opt.inputFile + " with a fake cert")
		generateCert(opt.domain, opt.inputFile)
		generatePFK(password, opt.domain)
		signExecutable(password, pfx, opt.inputFile, opt.outFile)

	}
	fmt.Println("[*] Cleaning up....")
	printDebug("[!] Deleting " + opt.domain + ".pem\n")
	os.Remove(opt.domain + ".pem")
	printDebug("[!] Deleting " + opt.domain + ".key\n")
	os.Remove(opt.domain + ".key")
	printDebug("[!] Deleting " + opt.domain + ".pfx\n")
	os.Remove(opt.domain + ".pfx")
	fmt.Println(color.GreenString("[+] ") + "Signed File Created.")

}

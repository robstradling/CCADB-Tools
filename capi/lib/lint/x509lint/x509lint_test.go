package x509lint

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const cert  = `-----BEGIN CERTIFICATE-----
MIIGozCCBIugAwIBAgIRAPkwq5XRBo9G6W+Me8AbALIwDQYJKoZIhvcNAQELBQAw
TTELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCUlkZW5UcnVzdDEqMCgGA1UEAxMhSWRl
blRydXN0IFB1YmxpYyBTZWN0b3IgUm9vdCBDQSAxMB4XDTE0MDMyODE3MjMxNVoX
DTIyMDMyODE3MjMxNVowYTELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCUlkZW5UcnVz
dDEgMB4GA1UECxMXSWRlblRydXN0IFB1YmxpYyBTZWN0b3IxHDAaBgNVBAMTE0lk
ZW5UcnVzdCBBQ0VTIENBIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDPvEZD2abX0Axa92t9YOUVh83LZQWerKNBi3n7ZCrDpMruJM1BLD11/4SQGWhm
BHK0m4XvrXsHo+fi43NHbARMDaEKEDBz3Uya6xGVGzpImpdKGVRfxd38YT9S2MS5
HoDm8LRTPsntYPnpD03igTCe6Bve+Flfj2PPlyn1MteoRaYP863usOZErWIQM20t
5PWxKn2t0EZBzpJSJvgTgZhlduTYM1m3Oc95rJRzn/U5vfeQfWPJiR1u+jydBjJL
8iiqoev4GwWl1UYXYY1cm5+sNJRZvVONS2o1aiZAf6wUoS2IdxNkanmOaNMw5Sil
TQ8mFglWCa8uGaLDVpvONqAXAgMBAAGjggJoMIICZDCBgQYIKwYBBQUHAQEEdTBz
MCwGCCsGAQUFBzABhiBodHRwOi8vcHVibGljLm9jc3AuaWRlbnRydXN0LmNvbTBD
BggrBgEFBQcwAoY3aHR0cDovL3ZhbGlkYXRpb24uaWRlbnRydXN0LmNvbS9yb290
cy9wdWJsaWNyb290Y2ExLnA3YzAfBgNVHSMEGDAWgBTjceCe2KdC2dtxkWuUk+vD
o9EUozAPBgNVHRMBAf8EBTADAQH/MIH3BgNVHSAEge8wgewwDAYKYIZIAWUDAgEB
ATAMBgpghkgBZQMCAQECMAwGCmCGSAFlAwIBAQMwDAYKYIZIAWUDAgEBBDAMBgpg
hkgBZQMCAQEIMAwGCmCGSAFlAwIBAQkwDAYKYIZIAWUDAgEBBTAMBgpghkgBZQMC
AQEKMAwGCmCGSAFlAwIBAQwwDAYKYIZIAWUDAgEBDTBeBgpghkgBZQMCAQEOMFAw
TgYIKwYBBQUHAgIwQhpAaHR0cHM6Ly9zZWN1cmUuaWRlbnRydXN0LmNvbS9jZXJ0
aWZpY2F0ZXMvcG9saWN5L2FjZXMvaW5kZXguaHRtbDBGBgNVHR8EPzA9MDugOaA3
hjVodHRwOi8vdmFsaWRhdGlvbi5pZGVudHJ1c3QuY29tL2NybC9wdWJsaWNyb290
Y2ExLmNybDA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMF
BggrBgEFBQcDBgYIKwYBBQUHAwcwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQG
zSi05Rxdv7o/rxIJQ4OdefzsMjANBgkqhkiG9w0BAQsFAAOCAgEAQRe6aVk0hHPC
uM8l/0deViGIMIEPbXUWkxlTtUxmipnc1JVi/YN5U8tKe5QDnb/Snt+UdGyyRQJT
P992j8dFw4JS5LRg0K561I6ZZo91/7CCy0lXvFXq9+LrUwYHbA8qyZGeLAvHZt9I
V5eRJE9NHrMPzjNOHqByIBmM85DsOMO1Mj0xGIBExOHi5UeMR7oeBCPLukPxSs5J
Aw8JX78TP0gABR+dv0CVdDlo8sWwGFTFinniq1Iwl4TUncnoR44m2RUoLYvQX9oW
gxwM6Op7um37+0XZ4s02W4Ob9Ae7B9ILSoLcRNT+4osK8l5e6PFXyf3aIxb82Oq8
DpshoZ1M+tmOFyM4sw3yxj4za2fxkE2umSVnwnaH2n9NreIK1y9pffrl6YfiwofN
wZBARjCLco+9ATvMh0B8ZcKOUrOet4JPWsdbUkcTyv1DWXBKPP2Yf+R05IFLpL4L
DzlU5S0MqTC0BuUnPTa2tRbiCsX+m9tqhELYzdc+vooYpvdnoAVqRe3mWSxCfNXb
KtVDpjcEjiTsIYEJABxnh886kp8y/sCUoCihzCGUHnIAC3hp94Ea7FPEWwJ7n8Xc
hqDcuFR0sxMz6uf3cTD/Iaqh7JZC15Bd2aX0sQVEcyWEyBR8mYTO8pzGX32jrIjR
XMeehE9yNnE/M0ZDY5dAAjrLj0BQar8=
-----END CERTIFICATE-----`


func TestIt(t *testing.T) {
	b, _ := pem.Decode([]byte(cert))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	l := Lint(c)
	t.Log(l)
}

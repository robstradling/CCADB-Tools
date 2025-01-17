/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* The following code is adapted from code from:
* https://github.com/mozilla/tls-observatory/blob/7bc42856d2e5594614b56c2f55baf42bb9751b3d/certificate/certificate_test.go */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestGetHexASN1Serial(t *testing.T) {
	type testcase struct {
		input  *x509.Certificate
		output string
	}
	testcases := []testcase{
		{
			&x509.Certificate{SerialNumber: big.NewInt(-1)},
			"FF",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(1)},
			"01",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(0)},
			"00",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(201)},
			"00C9",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(-201)},
			"FF37",
		},
	}
	for _, tc := range testcases {
		serial, _ := GetHexASN1Serial(tc.input)
		if serial != tc.output {
			t.Errorf("Expected %s, got %s", tc.output, serial)
		}
	}
}

var mozTechnicallyConstrained = []byte(`-----BEGIN CERTIFICATE-----
MIIHTDCCBjSgAwIBAgINAecH0ddtF7+K4cYQiTANBgkqhkiG9w0BAQsFADBjMQsw
CQYDVQQGEwJCRTEVMBMGA1UECxMMVHJ1c3RlZCBSb290MRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMSIwIAYDVQQDExlUcnVzdGVkIFJvb3QgQ0EgU0hBMjU2IEcy
MB4XDTE4MDExNzAwMDAwMFoXDTIzMDExNzAwMDAwMFowgYcxCzAJBgNVBAYTAlVT
MRswGQYDVQQKExJGb3JkIE1vdG9yIENvbXBhbnkxETAPBgNVBAcTCERlYXJib3Ju
MREwDwYDVQQIEwhNaWNoaWdhbjE1MDMGA1UEAxMsRm9yZCBNb3RvciBDb21wYW55
IC0gRW50ZXJwcmlzZSBJc3N1aW5nIENBMDEwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDSo24yvoHjFxQ6mRA/JVncVa4TdGJTy1DXWsN2QXE/aTzvxtAp
jgZ+J2jWiTiBXbLFSCCEcrlqd9R7GfGmzvHlJldZO340FS+caConYvsdZOFfCVKA
2AlJwZXiPXiq9q13hlxKTuKDpx7eqdhrseuJzFSb/mR3gy1hHW4XvIqkQXRY2ZTO
nQqgwxOQEirVYkBGWZrmE7pd+P2Pbm0Oy3IKfmPgRr26qLaLflhuiof3S0z3xGdF
8NDAQKiUF0FHxrm6I2wppdZrsEtuavK/JttbAUg+2u/PiWb6EoBVURQ7cV8gJhQ4
Mf77I+DJqCtg3MmlaEqwWtHSoF+tiu5kyD/5AgMBAAGjggPYMIID1DAOBgNVHQ8B
Af8EBAMCAQYwgZ0GA1UdJQSBlTCBkgYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEF
BQcDCQYIKwYBBQUHAw4GCisGAQQBgjcKAwQGCysGAQQBgjcKAwQBBgorBgEEAYI3
CgMLBgorBgEEAYI3FAIBBgorBgEEAYI3FAICBgkrBgEEAYI3FRMGCSsGAQQBgjcV
BQYJKwYBBAGCNxUGBgorBgEEAYI3CgMMMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
VR0OBBYEFIPFhTmtaeDfsuzUbTSm6/kGvWeeMB8GA1UdIwQYMBaAFMhjmwhpVMKY
yNnN4zO3UF74yQGbMIGNBggrBgEFBQcBAQSBgDB+MDcGCCsGAQUFBzABhitodHRw
Oi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vdHJ1c3Ryb290c2hhMmcyMEMGCCsGAQUF
BzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC90cnVzdHJv
b3RzaGEyZzIuY3J0MIIBoAYDVR0eBIIBlzCCAZOgggFdMAuBCS5mb3JkLmNvbTAR
gQ9haXMtY29sb2duZS5jb20wE4ERYWlzLXNhYXJsb3Vpcy5jb20wDYELY290YXJr
by5jb20wEoEQZXVyb3BlYW4tbGxwLmNvbTAKgQhmb3JkLmNvbTAQgQ5mb3JkY3Jl
ZGl0LmNvbTAQgQ5mb3JkZGlyZWN0LmNvbTARgQ9mb3Jzb25vcmRpYy5jb20wDYEL
bGluY29sbi5jb20wEIEObGluY29sbmFmcy5jb20wDIEKdHJveWRtLmNvbTAKgghm
b3JkLmNvbTBUpFIwUDELMAkGA1UEBhMCVVMxGzAZBgNVBAoTEkZvcmQgTW90b3Ig
Q29tcGFueTERMA8GA1UEBxMIRGVhcmJvcm4xETAPBgNVBAgTCE1pY2hpZ2FuMC+k
LTArMRMwEQYKCZImiZPyLGQBGRYDY29tMRQwEgYKCZImiZPyLGQBGRYEZm9yZKEw
MAqHCAAAAAAAAAAAMCKHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
MD4GA1UdHwQ3MDUwM6AxoC+GLWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vdHJ1
c3Ryb290c2hhMmcyLmNybDBaBgNVHSAEUzBRMAwGCisGAQQBge4xCgEwQQYJKwYB
BAGgMgE8MDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29t
L3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQA1X07Sm0BkKpg9GbEouL1C
zob9nM94esEZkQL69szSN75evgs5XulK/K4dQcXcN5y0kontEaaMZCG+T3mHDfbZ
Ru9GeITG4C9o+JzRZ+aUA71+1pzkrtCMc6QtaMziVSoGARswXuf8m7q0lNjnBYb6
lESAdtFzOitRf9436UiESrsWrOZQSX0ejR+L09vfWwCXoZfhmADvFeWtm7GBnN7k
1h1eVHay8uFCl4XrUPMZmBxw6ev1RGXjPIF8VtZAywkdY5u+XzH2NDQdeJPGih3Y
03K7PYtOSccYXKbsV+XEtgFN7fBFTuODihb4ygJVtwP+M/CGyRwtEZM2j7OHhM2F
-----END CERTIFICATE-----`)

// This cert has the EmailProtection EKU but does not fulfill
// the name constraint.
var mozNotTechnicallyConstrained = []byte(`-----BEGIN CERTIFICATE-----
MIII9TCCBt2gAwIBAgIIBrhoC897Tn4wDQYJKoZIhvcNAQEFBQAwgaoxCzAJBgNV
BAYTAkVTMRswGQYDVQQKExJBQyBDYW1lcmZpcm1hIFMuQS4xEjAQBgNVBAUTCUE4
Mjc0MzI4NzFLMEkGA1UEBxNCTWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0
IGh0dHBzOi8vd3d3LmNhbWVyZmlybWEuY29tL2FkZHJlc3MpMR0wGwYDVQQDExRB
QyBDYW1lcmZpcm1hIC0gMjAwOTAeFw0xNDExMjQxMTA3NTVaFw0yNDExMjExMTA3
NTVaMGUxCzAJBgNVBAYTAkVTMSUwIwYDVQQKDBxPUkdBTklaQUNJT04gTUVESUNB
IENPTEVHSUFMMSEwHwYDVQQLDBhFTlRJREFEIERFIENFUlRJRklDQUNJT04xDDAK
BgNVBAMMA09NQzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALRbioOD
0Dw7bglJNJ2yPMUoiQgMwJwGqAvMMbwEv8DGHW1mYOJEvxSLqub0lZSocUkh1o+s
wiBlATGXsuql995MDoRhbR9flyPv09FUBFXWySSsrOjpSDiMGMmaz3vB1oa0+t4k
kdcHj+Xb7rq0XNvWpklvZxbt/ng7UjKvkgPsSOEO0BA3L0KwUQVlRjogxRvVFR15
/X/GVpEVOwcLcb7qVI/W5gzMF2cnXNEXwJuiwPhg3Wlbk6VLppDLKrhIQagOgfqC
GxGBXYHWGnTNl/0HpHcx8HbvvB5zZLdQA5HfNHNZ19hGXjGoUotTN5dEhPDnQ91N
iGUzhdYj3NFKL3BGOSgBCZQayTZf1gz1MQsEjNS2MOYhxUuVYalXeQnL+vvuTGlB
3Kii+/X2KrNo4Af5yM2+n73da6fP9G7koT7fQBQRgZ3CRoNasMgb0QwGVzNCS5y1
g2BUPBQVDN+JV/JyeN9DCrYbm68kfufOYtyj2rp/dRgYANFtSJGZwRumKjqZ7QuZ
DRJjEorcGABHVuiAwv3jgfPoYaIQ92rtT+vbkponzE8SdBXVoToWXS1JWxoJMxRa
e2+KZhLOcfHbaZCtITMSmPZrJdtdr+QFvAJReXXXOylf9j4irKVxkXsE2RrfaN4H
F8hE5yOvgskgZEMPYQEtpsm6IjQv4EZ8lu6HAgMBAAGjggNhMIIDXTASBgNVHRMB
Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTnZBVkvqc1vvc6Ts8tPgcLt14/KzCB2QYD
VR0jBIHRMIHOgBTIAA/8xlL8n9s7ZC4yuW4ucfNleaGBsqSBrzCBrDELMAkGA1UE
BhMCRVUxQzBBBgNVBAcTOk1hZHJpZCAoc2VlIGN1cnJlbnQgYWRkcmVzcyBhdCB3
d3cuY2FtZXJmaXJtYS5jb20vYWRkcmVzcykxEjAQBgNVBAUTCUE4Mjc0MzI4NzEb
MBkGA1UEChMSQUMgQ2FtZXJmaXJtYSBTLkEuMScwJQYDVQQDEx5HbG9iYWwgQ2hh
bWJlcnNpZ24gUm9vdCAtIDIwMDiCAQIwegYIKwYBBQUHAQEEbjBsMEIGCCsGAQUF
BzAChjZodHRwOi8vd3d3LmNhbWVyZmlybWEuY29tL2NlcnRzL2FjX2NhbWVyZmly
bWEtMjAwOS5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLmNhbWVyZmlybWEu
Y29tMA4GA1UdDwEB/wQEAwIBBjAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUH
AwQGCCsGAQUFBwMJMD4GA1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1o
dHRwczovL3BvbGljeS5jYW1lcmZpcm1hLmNvbTB6BgNVHR8EczBxMDagNKAyhjBo
dHRwOi8vY3JsLmNhbWVyZmlybWEuY29tL2FjX2NhbWVyZmlybWEtMjAwOS5jcmww
N6A1oDOGMWh0dHA6Ly9jcmwxLmNhbWVyZmlybWEuY29tL2FjX2NhbWVyZmlybWEt
MjAwOS5jcmwwgdoGA1UdEQSB0jCBz4EWY2VydGlmaWNhY2lvbkBjZ2NvbS5lc6SB
tDCBsTELMAkGA1UEBhMCRVMxDzANBgNVBAgTBk1BRFJJRDEPMA0GA1UEBxMGTUFE
UklEMQ4wDAYDVQQREwUyODAxNDEfMB0GA1UECRMWUExBWkEgREUgTEFTIENPUlRF
UyAxMTESMBAGA1UEBRMJUTI4NjYwMTdDMTswOQYDVQQDFDJDT05TRUpPIEdFTkVS
QUwgREUgQ09MRUdJT1MgREUgTcOJRElDT1MgREUgRVNQQcORQTANBgkqhkiG9w0B
AQUFAAOCAgEAhODURFs76WtpihhB6y5etlbWk5TrHqsckgRrqA/UMUEajSxSlHbC
JQ3lz9vzJW/dQHw77RlJBQJvAY3II/s5bRsG+TbEA2f4XLY1fchU+lYY8suilbEY
MnorKfl1uP9y+aF7OCtLHY1Wt0MYccKwUtNgrozTwMgPbwCo3e4mTdWgg1Vvu573
jFmopi5Agzzcth8ruHmAlp1tSqZOs8NKExZ9k1tkFiuDtrdFqOUi/4vx9LQKFm9E
aaoB1vDAbU5KCyOZrq+dvwpHz9B5EN0995a68k/8dmMsAmL4qXrSLVJ66ugm0HUK
7xBwTHZhi3Nz5HvyJHpmkccUmEbVEjxLrKpJc80xjw2HlQV+uvUP0jUyLwm+9RV+
d4cEQ3Js8WLmUjseHm68gI2Ivv0kPDVpUCyUADRkFfnN4YHp54kaNNXI/Wr12hA3
J80RDyPY+9DfU9DfGfybtu5Eoc/Cl5jumoUDuVghRPxpByWp+dNOFJtWCD8I/9QI
OmribtK9mjEZVNm/CqIjwhcI5D737n6QKOEapJVCmDFj2UwiAS9pVR4gqNY9cHkU
lfT06yBl+QBe3mZV6JLi3Lq6U6Blfi8+eWaGD7TkopVYJl+eR/4vUGVH5f5s0Wdg
lMlvG5avdIGZyTT+ktD3R0wJ/WGAUviweDBSGb+oUmUaBV7igHuZ/ws=
-----END CERTIFICATE-----`)

func TestMozillaPolicy(t *testing.T) {
	block, _ := pem.Decode(mozTechnicallyConstrained)
	cert, _ := x509.ParseCertificate(block.Bytes)
	mozPolicy := getMozillaPolicyV25(cert)
	if !mozPolicy.IsTechnicallyConstrained {
		t.Errorf("Wrong Mozilla Technical Constraint value. Got %v, wanted %v", mozPolicy.IsTechnicallyConstrained, true)
	}
}

func TestMozillaPolicyNotTechnicallyConstrained(t *testing.T) {
	block, _ := pem.Decode(mozNotTechnicallyConstrained)
	cert, _ := x509.ParseCertificate(block.Bytes)
	mozPolicy := getMozillaPolicyV25(cert)
	if mozPolicy.IsTechnicallyConstrained {
		t.Errorf("Wrong Mozilla Technical Constraint value. Got %v, wanted %v", mozPolicy.IsTechnicallyConstrained, false)
	}
}

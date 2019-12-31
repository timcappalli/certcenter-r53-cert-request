# CertCenter + Amazon Route 53 Cert Request

This is a basic script that automates requests for certificates from AlwaysOnSSL (DigiCert) via CertCenter when the domain's name server is Amazon Route 53.

What it does:
1. Checks the domain against CertCenter for eligibility 
2. Requests domain validation challenge (TXT record)
3. Creates TXT record in AWS
4. Verifies the TXT record has been created, that it has propagated and that the value matches
5. Submits the CSR for signing
6. Dumps out the signed cert with chain
7. Deletes TXT record



## Configuration
Create a file called 'config' with the contents below and fill in the appropriate values.

```
[CertCenter]
client_id = 
client_secret = 
product_code = AlwaysOnSSL.AlwaysOnSSL
cert_validity_period = 365

[AWS]
hosted_zone_id = 
aws_access_key_id = 
aws_secret_access_key = 
```

## Usage

`request_cert.py -f/--fqdn <subject-fqdn> -c/--csr <csr-filename> [-v/--validity <days>]`

Required Arguments:
* `--fqdn / -f`: The FQDN from the CN
* `--c / -c`: the filename of ot he CSR

Optional Arguments:
* `--days / -d`: override validity from config file (1-365)
* `--verbose / -v`: verbose logging 

### Example

`request_cert.py --fqdn=host.domain.com --csr=host.csr `
`request_cert.py -f host.domain.com -c host.csr`

## Change Log
### 2019.02 (2019-12-31)
* Fixed an issue where the root certificate and extra blank lines were included in the chained output due to an undocumented change by DigiCert

### 2019.01 (2019-09-19)
* Initial release

## License and Other Information
This repo is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

Author: @timcappalli
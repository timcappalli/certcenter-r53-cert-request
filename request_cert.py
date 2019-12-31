#!/usr/bin/env python3
#------------------------------------------------------------------------------
#
# Name: cert_request.py
# Usage:
#
# Version: 2019.02
# Date: 2019-12-31
#
# Author: @timcappalli
#
# (c) Copyright 2019 Tim Cappalli.
#
# Licensed under the MIT license:
#
#    http://www.opensource.org/licenses/mit-license.php
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#------------------------------------------------------------------------------

__version__ = "2019.02"

import json
import requests
import boto3
import dns.resolver
import time
import os
from configparser import ConfigParser
import argparse
import pem

# configuration file parameters
params = os.path.join(os.path.dirname(__file__), "config")
config = ConfigParser()
config.read(params)

# CertCenter config
CC_PRODUCT_CODE = config.get('CertCenter', 'product_code')
CC_CERT_VALID_CONFIG = config.get('CertCenter', 'cert_validity_period')

CC_CLIENT_ID = config.get('CertCenter', 'client_id')
CC_CLIENT_SECRET = config.get('CertCenter', 'client_secret')
CC_TOKEN_ENDPOINT = 'https://api.certcenter.com/oauth2/token'
CC_SCOPE = 'order'

# AWS config
r53_hosted_zone_id = config.get('AWS', 'hosted_zone_id')
aws_access_key_id = config.get('AWS', 'aws_access_key_id')
aws_secret_access_key = config.get('AWS', 'aws_secret_access_key')
r53client = boto3.client('route53', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

# Cert values (static for testing)
#cert_fqdn = "8A1B0816-84F5.central-poc.clearpass.boston"

# Import CSR (static for testing)
#file_import = open("csr.pem","r")
#csr = file_import.read()


def token_handling():

    if os.path.isfile("token.json"):

        with open('token.json') as f:
            token_file = json.load(f)

        current_time_plus_thirty = time.time() + 30

        ### check cached token validity
        if token_file['expires_at'] > current_time_plus_thirty:
            access_token = token_file['access_token']
            print("\tUsing cached access token.\n")
            return(access_token)

    else:
        ### check config.py
        if not CC_CLIENT_ID or not CC_CLIENT_SECRET:
            print("ERROR: client_id or client_secret not defined in config.")
            exit(1)
        else:
            ### get new token
            print("\tNo cached token. Acquiring new token.")

            url = CC_TOKEN_ENDPOINT
            headers = {'Content-Type': 'application/json'}
            payload = {'grant_type': 'client_credentials', 'client_id': CC_CLIENT_ID, 'client_secret': CC_CLIENT_SECRET, 'scope': CC_SCOPE}

            try:
                r = requests.post(url, headers=headers, json=payload)
                r.raise_for_status()

                json_response = json.loads(r.text)

                if DEBUG:
                    print(json_response)

                ### token caching
                token_expiration = int(json_response['expires_in'] + time.time())
                token_cache = {'access_token': json_response['access_token'], 'expires_at': token_expiration, 'host': CC_TOKEN_ENDPOINT}
                with open('token.json', 'w') as tokenfile:
                    json.dump(token_cache, tokenfile)

                return json_response['access_token']

                # TODO: add refresh token

            except Exception as e:
                if r.status_code == 400:
                    print("ERROR: Check config (client_id, client_secret)")
                    print("\tRaw Error Text: {}".format(e))
                    exit(1)
                else:
                    print(e)
                    exit(1)


def cc_validate_name(cc_access_token, cert_fqdn):
    """Validate FQDN for certificate eligibility against CertCenter API

    Requires CertCenter access token and requested FQDN

    """
    try:
        url = "https://api.certcenter.com/rest/v1/ValidateName"

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(cc_access_token)
        }

        payload = {
            "CommonName": cert_fqdn
        }

        r = requests.post(url=url, headers=headers, json=payload)

        json = r.json()

        if not json['success']:
            print("\n\tCertCenter authorization failed. Check access token.")
            print("\n\t\t{}".format(r.text))
            exit(1)
        elif json['IsQualified']:
            print("\n\tAuthorization successful! Domain qualified.")
            return json
        else:
            print("\n\tUnknown error.")
            print("\n\t\t{}".format(r.text))
            exit(1)

    except Exception as e:
        print("\n\t{}".format(e))
        exit(1)


def cc_get_dns_data(cc_access_token, csr, cc_product_code):
    """Get DNS validation data via CertCenter REST API

    Requires CertCenter access token and CSR for FQDN

    """

    try:
        url = "https://api.certcenter.com/rest/v1/DNSData"

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(cc_access_token)
        }

        payload = {
            "CSR": csr,
            "ProductCode": cc_product_code
        }

        r = requests.post(url=url, headers=headers, json=payload)
        json = r.json()

        txt_value = json['DNSAuthDetails']['DNSValue']
        txt_example = json['DNSAuthDetails']['Example']

        print("\n\t{}".format(txt_example))

        return txt_value

    except Exception as e:
        print("\n\t{}".format(e))
        exit(1)

# TODO: add check for CAA record


def r53_add_txt_record(cert_fqdn, r53_hosted_zone_id, txt_value):
    """Add TXT record for FQDN in Amazon Route53

    Requires FQDN, Route53 hosted zone ID and the desired TXT value

    """

    try:
        response = r53client.change_resource_record_sets(
            HostedZoneId=r53_hosted_zone_id,
            ChangeBatch={
                'Comment': "pycharm",
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': cert_fqdn,
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': "\"{}\"".format(txt_value)}]
                        }
                    }]
            })

        print("\n\tTXT record created in Route53!")

    except Exception as e:
        print("\n\t{}".format(e))
        exit(1)


def verify_dns_record(cert_fqdn, txt_value):
    """Verify DNS record matches and record has propagated to Google DNS

    Requires FQDN and expected TXT value from CertCenter

    """

    found = False

    print("\n\tWaiting 30 seconds for global DNS propagation...")
    time.sleep(30)

    while not found:
        try:
            dns_resolver = dns.resolver.Resolver()
            dns_resolver.nameservers = ['8.8.8.8']
            dns_answers = dns_resolver.query(cert_fqdn, "TXT")

            found = True

            print("\n\tRecord found! Verifying...")

            time.sleep(3)

            for rdata in dns_answers:

                value = str(rdata)

                if value == "\"{}\"".format(txt_value):
                    accurate = True
                else:
                    accurate = False

        except:
            found = False
            print("\n\tDNS record still not found. Waiting another 30 seconds before next lookup attempt...")
            time.sleep(30)

    if accurate:
        print("\n\tTXT record matches!")
        return True
    else:
        print("\n\tTXT record does NOT match")
        exit(1)


def cc_request_cert(cc_access_token, csr, cc_product_code, cc_cert_validity_period):
    """Request certificate from CertCenter via REST API

    Requires CertCenter access token, CSR (PKCS #10 format), CertCenter product code and cert validity period

    """
    try:
        url = "https://api.certcenter.com/rest/v1/Order"

        headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(cc_access_token)}

        payload = {
            "OrderParameters": {
                "ProductCode": cc_product_code,
                "CSR": csr,
                "ValidityPeriod": int(cc_cert_validity_period),
                "DVAuthMethod": "DNS"
            }
        }

        r = requests.post(url=url, headers=headers, json=payload)

        json = r.json()

        if json['success']:
            results = {
                "pkcs7": json['Fulfillment']['Certificate_PKCS7'],
                "intermediate": json['Fulfillment']['Intermediate'],
                "signed_cert": json['Fulfillment']['Certificate'],
                "expiration": json['Fulfillment']['EndDate']
            }

            print("\n\tCertificate request succesful!\n\tExpiration: {}".format(json['Fulfillment']['EndDate']))

            return results

        else:
            print("\n\tCERTIFICATE REQUEST FAILED")
            print("\n\t\t{}".format(r.text))
            exit(1)

    except Exception as e:
        print("\n\t{}".format(e))
        exit(1)


def dump_cert(cert_fqdn, signed_cert, intermediate):
    """Dumps out cert and chained cert to files (PEM)

    Requires cert FQDN, signed cert and intermediate returned from CertCenter

    """
    try:
        file = open("{}_cert.pem".format(cert_fqdn), "w")
        file.write(signed_cert.strip())
        file.close()

        print("\n\tCertificate exported: {}_cert.pem".format(cert_fqdn))

    except Exception as e:
        print("\n\t{}".format(e))
        exit(1)

    intermediate_pem = pem.parse(intermediate.encode())
    intermediate_clean = str(intermediate_pem[0]).strip()

    try:
        file = open("{}_cert-chained.pem".format(cert_fqdn), "w")
        file.write(signed_cert)
        file.write(intermediate_clean)
        file.close()

        print("\n\tChained certificate exported: {}_cert-chained.pem".format(cert_fqdn))

    except Exception as e:
        print("\n\t{}".format(e))
        exit(1)


def r53_delete_txt_record(cert_fqdn, r53_hosted_zone_id, txt_value):
    """Delete TXT record for FQDN in Amazon Route53

    Requires FQDN, Route53 hosted zone ID and existing TXT value

    """
    try:
        response = r53client.change_resource_record_sets(
            HostedZoneId=r53_hosted_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': cert_fqdn,
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': "\"{}\"".format(txt_value)
                                }
                            ]
                        }
                    }]
            })

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print("\n\tSuccessfully requested TXT record deletion in Route53!")
            if DEBUG:
                print("\t\t{}".format(response['ChangeInfo']))

        else:
            print("TXT record could not be deleted: \n\t\"{}\"".format(response))
            exit(0)

    except Exception as e:
        print("TXT record could not be deleted: \n\t\"{}\"".format(e))
        exit(0)


if __name__ == '__main__':

    # process arguments
    parser = argparse.ArgumentParser(
        description='Cert request for CertCenter with Route 53 DNS'
    )

    required_args = parser.add_argument_group('Required arguments')
    required_args.add_argument("-f", "--fqdn", help="FQDN", required=True)
    required_args.add_argument("-c", "--csr", help="CSR filename", required=True)
    parser.add_argument("-d", "--days", help="Cert Validity in days, 1-365 (optional)", required=False)
    parser.add_argument("-v", "--verbose", help="Verbose logging", required=False, action='store_true')

    # TODO: add option for manual DNS
    # TODO: add optional option for hosted zone ID
    # TODO: add verbose logging

    DEBUG = False

    args = parser.parse_args()

    cert_fqdn = args.fqdn
    csr_filename = args.csr

    if args.verbose:
        DEBUG = True

    if args.days:
        validity_period = args.days
    else:
        validity_period = CC_CERT_VALID_CONFIG

    with open(csr_filename, 'r') as f:
        csr = f.read()

    # get CertCenter access token
    print("\n[1] Getting access token...")
    token = token_handling()

    # validate domain against CertSimple
    print("\n[2] Validating domain with CertCenter...")
    cc_validate_name(token, cert_fqdn)

    # get DNS validation value from CertSimple
    print("\n[3] Getting domain validation information from CertCenter...")
    txt_value = cc_get_dns_data(token, csr, CC_PRODUCT_CODE)

    # create DNS record in Route53
    print("\n[4] Creating TXT DNS record in Amazon Route53...")
    r53_add_txt_record(cert_fqdn, r53_hosted_zone_id, txt_value)

    # verify DNS propagation
    print("\n[5] Attempting to verify DNS record...")
    txt_match = verify_dns_record(cert_fqdn, txt_value)

    # request certificate
    print("\n[6] Requesting certificate from CertCenter...")
    cert_output = cc_request_cert(token, csr, CC_PRODUCT_CODE, validity_period)

    # dump signed certificate to file
    print("\n[7] Exporting signed certificate with chain...")
    dump_cert(cert_fqdn, cert_output.get('signed_cert'), cert_output.get('intermediate'))

    # delete TXT record
    print("\n[8] Attempting to delete TXT record for \"{}\"".format(cert_fqdn))
    r53_delete_txt_record(cert_fqdn, r53_hosted_zone_id, txt_value)

    print("\n\nPROCESS COMPLETE!\n\n")
    exit(0)

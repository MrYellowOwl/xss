import argparse
import requests
from urllib.parse import urlparse, urlunparse, urlsplit
from bs4 import BeautifulSoup
import sys
import time
from colorama import Fore, Style

def obtain_cookies(session, url):
    # Remove the fragment part from the URL
    url_without_fragment = urlsplit(url)._replace(fragment='').geturl()

    try:
        response = session.get(url_without_fragment)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining cookies: {e}")
        return None

    return response.cookies

def test_payloads(session, url, payloads, cookies):
    vulnerable_payloads = []

    total_payloads = len(payloads)
    for i, payload in enumerate(payloads, start=1):
        # Update the URL with the payload
        parsed_url = urlparse(url)
        updated_url = urlunparse(parsed_url._replace(query=f'q={payload}'))

        try:
            # Add cookies to the request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Referer': url
            }
            response = session.get(updated_url, headers=headers, cookies=cookies)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error testing payload {i}/{total_payloads} - {e}")
            # Continue to the next payload even if an error occurs
            continue

        if payload in response.text:
            vulnerable_payloads.append(updated_url)

        sys.stdout.write(f'Testing payload {i}/{total_payloads} - {updated_url}\n')
        sys.stdout.flush()

        # Add a delay between requests
        time.sleep(1)

    return vulnerable_payloads

def main():
    parser = argparse.ArgumentParser(description='Test XSS payloads on a specified search URL.')
    parser.add_argument('-u', '--url', type=str, help='Search URL')
    parser.add_argument('-p', '--payload-file', type=str, required=True, help='Path to the file containing XSS payloads')
    parser.add_argument('-l', '--target-list', type=str, help='Path to the file containing a list of target URLs')

    args = parser.parse_args()
    payload_file = args.payload_file
    target_list_file = args.target_list

    if args.url and args.target_list:
        print("Please provide either a single URL (-u) or a target list (-l), not both.")
        sys.exit(1)

    if not args.url and not args.target_list:
        print("Please provide either a single URL (-u) or a target list (-l).")
        sys.exit(1)

    if args.url:
        targets = [args.url]
    else:
        with open(target_list_file) as target_file:
            targets = [line.strip() for line in target_file]

    with open(payload_file) as file:
        xss_payloads = [line.strip() for line in file]

    with requests.Session() as session:
        for target_url in targets:
            print(f'Testing Target URL: {target_url}')
            
            print(f'Obtaining cookies for URL: {target_url}')
            cookies = obtain_cookies(session, target_url)

            print('Cookies obtained successfully.' if cookies else 'Failed to obtain cookies.')

            print(f'Testing URL: {target_url}')
            vulnerabilities = test_payloads(session, target_url, xss_payloads, cookies)

            if vulnerabilities:
                print(Fore.GREEN + 'Vulnerable Payloads:')
                for payload in vulnerabilities:
                    print(Fore.GREEN + f'  {payload}')
            else:
                print('No vulnerabilities found.')

if __name__ == '__main__':
    main()

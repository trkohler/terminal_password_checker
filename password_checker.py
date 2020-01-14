import requests
import hashlib
import sys

URL_BASE = 'https://api.pwnedpasswords.com/range/'


def request_data(query_char: str):
    url = URL_BASE + query_char
    response = requests.get(url)
    if response.status_code != 200:
        print(f'Something is wrong. Response is: {response.status_code}. Please try again.')
        # I don't want to have an useless response.
    else:
        return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pnwed_api_check(password: str):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # sha1 returns an object, then I use method to get a string, then I make string letter uppercase
    # I do this because api requires it this way
    first5_char, tail = sha1password[0:5], sha1password[5:]
    response = request_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pnwed_api_check(password)
        if count:
            print(f'{password} was found {count} times. Are you sure about using the one?')
        else:
            print(f'{password} was NOT found. It must be strong!')
    pass


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

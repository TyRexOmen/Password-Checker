import hashlib  # hashlib allows us to do SHA1 hashing.
import sys  # allows us to interact with our command line to submit arguments for the password checker to check

import requests  # allows us to pull data from the API (pwnedpasswords)


def request_api_data(query_char):
    pass
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {
                           res.status_code}, check the api and try again.')
    return res


def gets_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in
              # this assists with formatting our hashes for readability.
              hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0



def pwned_api_check(password):
    # check password if it exists in API response
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[
        5:]  # Allows us to grab the 1st 4 characters and the tail to send to our API
    response = request_api_data(first5_char)
    print(first5_char, tail)
    return gets_password_leaks_count(response, tail)


def main(args):  # Receive arguments in our command line
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {
                  count} times.... you should probably change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

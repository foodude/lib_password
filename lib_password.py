"""
A collection of example functions to interact with passwords.
"""

import logging as log
import getpass
import string
import time
import secrets
import bcrypt



def get_password_from_stdin(**args):
    """
    info:
        Get password from stdin

    args:
        [confirm] <bool>
            If confirm is True you will be forced to type
            the password again

        [retries] <int>
            Number of retries when password and confirmed password
            did not match.
            Default 3

        [message_enter] <str>
            Message for entering password
            Default: Enter password:

        [message_confirm] <str>
            Message for confirming password
            Default: Confirm password:

    return:
        password | False

    """
    confirm = args.get('confirm', True)
    retries = args.get('retries', 3)
    message_enter = args.get('msg_enter', 'Enter password: ')
    message_confirm = args.get('msg_confirm', 'Confirm password: ')

    if confirm:
        for i in reversed(range(retries)):
            pwd = getpass.getpass(message_enter)
            check_pwd = getpass.getpass(message_confirm)
            if pwd == check_pwd:
                return pwd

            log.warning(f'Password did not match, {i} retries left')

    else:
        return getpass.getpass(message_enter)

    return False



def generate_password(**args):
    """
    info:
        Generate a random password

    args:
        [length] <int>
            Length of the password
            Default: 8

        [alphabetical] <bool>
            Alphabetical cjaracters
            Default: True

        [numerical] <bool>
            Numerical characters
            Default: True

        [punctuation] <bool>
            Punctuation characters
            Default: True

    return:
        str
    """
    length = args.get('length', 8)

    characters = {
        'alphabetical': string.ascii_letters,
        'numerical': string.digits,
        'punctuation': '!@#$%^&*()'}

    selected_characters = ''.join(
        characters[x] for x in ['alphabetical', 'numerical', 'punctuation']
            if args.get(x, True))

    return ''.join(secrets.choice(selected_characters) for _ in range(length))



def check_password_length(**args):
    """
    info:
        Check if password has a given length

    args:
        [password] <str>
            Password that will be checked. If password is None (default)
            it will be set from stdin

        [length] <int>
            Length of the password
            Default: 8

    return:
        True | False

    """
    password = args.get('password') or get_password_from_stdin(confirm=False)
    length = args.get('length', 8)

    if len(password) <= length:
        log.warning('Password length is to short: %s < %s',
                    len(password),
                    length)
        return False

    return True



def check_password_characters(**args):
    """
    info:
        Check if a password consists of certain characters

    args:
        [password] <str>
            Password that will be checked .
            If password is None, it will be set via stdin.
            Default: None

        [alphabetical] <bool>
            Check for alphabetical characters
            Default: True

        [numerical] <bool>
            Check for numerical characters
            Default: True

        [uppercase] <bool>
            Check for uppercase characters
            Default: True

        [lowercase] <bool>
            Check for lowercase characters
            Default: True

        [punctuation] <bool>
            Check for punctuation characters
            Default: True

    return:
        True | False
    """
    password = args.get('password') or get_password_from_stdin(confirm=False)

    checks = {
        'alphabetical': string.ascii_letters,
        'numerical': string.digits,
        'uppercase': string.ascii_uppercase,
        'lowercase': string.ascii_lowercase,
        'punctuation': string.punctuation}

    for check, characters in checks.items():
        if args.get(check, True) is True:
            if not [x for x in password if x in characters]:
                log.warning(f'Password must contain {check} characters.')
                return False

    return True



def create_password_hash(**args):
    """
    info:
        Return password hash

    args:
        [password] <str>
            Password that will be hashed. If password is None (default),
            the password will be set from stdin

    return:
        hash
    """
    password = args.get('password') or get_password_from_stdin(confirm=False)
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())



def check_password(**args):
    """
    info:
        Check if password matches with a given password hash

    args:
        [password] <str>
            Password tha will be checked. If none is specified (default),
            it will be set via stdin

        [password_hash] <str>
            The password hash, that will be checked against the password

        [message_enter] <str>
            Stdin message for entering password

        [max_retries] <int>
            Maximum retries for entering password
            Default: 3

        [retry_time_interval] <int>
            Seconds to wait for retry
            Default: 2

    return:
        True | False
    """
    password_hash = args.get('password_hash', None)
    max_retries = args.get('max_retries', 3)
    retry_time_interval = args.get('retry_time_interval', 2)
    message_enter = args.get('message_enter', 'Enter password: ')

    if not password_hash:
        log.error('arg: [password_hash] is required but missing!')
        return False

    if args.get('password'):
        return bcrypt.checkpw(args.password.encode('utf-8'), password_hash)

    for retries in reversed(range(max_retries)):
        if bcrypt.checkpw(
                get_password_from_stdin(
                    confirm=False,
                    message_enter=message_enter).encode('utf-8'),
                password_hash):
            return True

        if retries == 0:
            log.warning('Wrong password: Max retries elapsed')
            return False

        log.warning('Wrong password: [%s] retries, in [%s] seconds',
                    retries,
                    retry_time_interval)
        time.sleep(retry_time_interval)



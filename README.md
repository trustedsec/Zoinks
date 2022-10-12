usage: zoinks.py [-h] [-v] [-d {auto,pycryptodome,cryptography}] [-x] [-p DATABASE_PASSWORD] [-a AES_ENCRYPTION_KEY]
                 [-n NOTES_DESCRIPTION] [-u USER_PASSWORD]

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

options:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity, log messagse are sent to stderr
  -d {auto,pycryptodome,cryptography}, --dependency {auto,pycryptodome,cryptography}
                        select from the supported python cryptography packages
                        defaults to: auto
  -x, --no-interaction  suppress prompts, working only with the arguments provided
  -p DATABASE_PASSWORD, --database-password DATABASE_PASSWORD
                        the value for password stored in the conf/database-params.conf file
  -a AES_ENCRYPTION_KEY, --aes-encryption-key AES_ENCRYPTION_KEY
                        the value for ENCRYPTIONKEY stored in the conf/pmp_key.key file
  -n NOTES_DESCRIPTION, --notes-description NOTES_DESCRIPTION
                        the value of the notesdescription column stored in the database
                        (SELECT * FROM Ptrx_NotesInfo)
  -u USER_PASSWORD, --user-password USER_PASSWORD
                        the value of the decrypted password column stored in the database
                        (see the blog post for more info on the correct query to obtain this)



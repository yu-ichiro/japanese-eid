import sys
from typing import List, cast

from pkcs11 import PublicKey, lib, Token, Session
from pkcs11.util.rsa import encode_rsa_public_key
from Crypto.PublicKey import RSA

lib = lib('/Library/OpenSC/lib/opensc-pkcs11.so')


def get_tokens() -> List[Token]:
    return list(lib.get_tokens())


def get_auth_pubkey(session: Session) -> PublicKey:
    return cast(PublicKey, session.get_key(PublicKey.object_class, id=b'\x01'))


def main():
    token = get_tokens()[0]
    session = token.open()
    print(token.label, file=sys.stderr)

    pubkey = get_auth_pubkey(session)
    der = encode_rsa_public_key(pubkey)
    rsa = RSA.importKey(der)
    print(pubkey.label, file=sys.stderr)
    print(rsa.export_key('OpenSSH').decode())

    session.close()


if __name__ == '__main__':
    main()

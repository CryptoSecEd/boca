"""This script will prompt the user for a password, generate a new
BCH/tBCH/ETH private key, encrypt it with the password and save it to
a file (argument). The address(es) will be printed to the screen.
"""

import sys

from argparse import ArgumentParser
from pathlib import Path

from boca.crypto import enc_keys
from boca.blockchain import gen_bch, gen_tbch, gen_eth, change_null


def main():
    """Create a file to save the password-protected private key."""
    parser = ArgumentParser(description="Generate a private key for BCH" +
                            " and/or ETH.")
    parser.add_argument("--keyfile", help="File to save the encrypted " +
                        "private key.", default="private.key")
    parser.add_argument("--BCH", help="Generate a BCH private key.",
                        action="store_true")
    parser.add_argument("--tBCH", help="Generate a (testnet) BCH private key.",
                        action="store_true")
    parser.add_argument("--ETH", help="Generate an ETH private key.",
                        action="store_true")

    args = parser.parse_args()
    args = change_null(args)

    if not (args.BCH or args.tBCH or args.ETH):
        print("You must specify at least one type of private key to " +
              "generate: --BCH, --tBCH, or --ETH")
        sys.exit(1)

    keyfile = Path(args.keyfile)

    if keyfile.is_file():
        print(f"There already exists a file named {str(keyfile)}. Please " +
              "specify a different file name.")
        sys.exit(1)

    keys = {}

    if args.BCH:
        keys['BCH'] = gen_bch()

    if args.tBCH:
        keys['tBCH'] = gen_tbch()

    if args.ETH:
        keys['ETH'] = gen_eth()

    enc_keys(keys, args.keyfile)
    print(keys)


if __name__ == "__main__":
    main()

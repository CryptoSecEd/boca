"""This script checks a boca post on a blockchain. The hash of the file
provided/index file, will be checked against a hash obtained from a
blockchain. The transaction ID can be given directly. Or an address can
be provided and the script will search all transactions for that
address. If neither is given, then it will check if there are addresses
that have a mutual exchange with the local wallet. If there is exactly
one, it will use that address. If there are multiple, it will give the
user a choice.
Decryption uses the private key from the wallet.
Data transfer needs to be performed by the user (see boca-verify-ipfs.py
to use the IPFS to exchange data).
If the received data is a folder, an 'index.txt' will be searched for.
If found, all hashes contained within will be checked.
"""

import sys
import zipfile

from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from cashaddress.convert import to_cash_address, InvalidAddress
from requests.exceptions import HTTPError

from boca.blockchain import BOCError, change_null, get_boc_hash, find_mutual
from boca.blockchain import check_post_from_address, select_mutual
from boca.crypto import dec_file, hmac_file, key_manager, DecryptionError
from boca.ipfs import check_index, hash_file, unzip_file, HashError


def main():
    """Verify if a file/folder matches a hash posted to a blockchain
    using BoCA.
    """
    parser = ArgumentParser(description="Verify data posted to the " +
                            "Blockchain using the Blockchain-of-" +
                            "Custody Application")
    parser.add_argument("--ID", help="Provide a transaction ID that " +
                        "has a posted hash.", type=str)
    parser.add_argument("--address", help="Provide an address that " +
                        "has one transaction with a posted hash.",
                        type=str)
    parser.add_argument("--path", help="This file will be hashed, and" +
                        " the hash verified against what has been " +
                        "posted to the blockchain. It can " +
                        "alternatively be a folder.", type=str)
    parser.add_argument("--keyfile", help="This file contains the " +
                        "encrypted private keys for accessing the " +
                        "blockchain(s).", default="private.key")
    parser.add_argument("--dec", help="Use if the provided file was " +
                        "encrypted. An attempt will be made to " +
                        "decrypt.", action="store_true")
    parser.add_argument("--chain", help="Specify which blockchain(s) " +
                        "to verify from (default is BCH)",
                        default="BCH")
    parser.add_argument("--hmac", help="Calculate a HMAC of the file" +
                        " instead of a hash (requires a password).",
                        type=str)

    args = parser.parse_args()
    args = change_null(args)

    # Only load the private keys if the 'dec' argument has been given or
    # there is no 'ID' and no 'address' or there is no path
    if (args.dec or not args.path or not (args.ID or args.address)):
        keys = key_manager(args.keyfile, args.chain)
        if args.chain == "BCH":
            print("Attempting to verify post to BCH blockchain")
            key = keys["BCH"]
        elif args.chain == "tBCH":
            print("Attempting to verify post to (testnet) BCH blockchain")
            key = keys["tBCH"]
        elif args.chain == "ETH":
            print("Attempting to verify post to ETH blockchain")
            key = keys["ETH"]
        elif args.chain == "tETH":
            print("Attempting to verify post to (testnet) ETH blockchain")
            key = keys["ETH"]
        else:
            print("Unknown blockchain: %s" % args.chain)
            print("Choose one of: BCH, tBCH, ETH, tETH")
            sys.exit(1)

    if args.path:
        input_path = Path(args.path)
        if input_path.is_dir():
            file_to_verify = Path(input_path, 'index.txt')
            if file_to_verify.is_file():
                try:
                    check_index(file_to_verify)
                except HashError:
                    print(("Hash failure against index file %s. Exiting " +
                          "program.") % file_to_verify)
                    sys.exit(1)
            else:
                print(("Folder does not contain an index file and so cannot " +
                       "be verified: %s") % file_to_verify)
                sys.exit(1)
        elif input_path.is_file():
            file_to_verify = input_path
        else:
            print(("Input path %s does not exist. Please specify a file or " +
                   "folder.") % args.path)
            sys.exit(1)

    if args.dec:
        file_to_decrypt = Path(args.path)
        if file_to_decrypt.is_dir():
            print("Unable to decrypt folder %s. Please specify a file." %
                  file_to_decrypt)
        try:
            decrypted_file = dec_file(key, file_to_decrypt, args.chain)
        except DecryptionError as error:
            print(error.args[0])
            sys.exit(1)
        except ValueError as error:
            print(error.args[0])
            sys.exit(1)
        try:
            output = unzip_file(decrypted_file)
            if output == 0:
                file_to_verify = decrypted_file
            else:
                if len(output) == 1:
                    only_folder = Path(output.pop())
                    file_to_verify = Path(only_folder, 'index.txt')
                    if file_to_verify.is_file():
                        try:
                            check_index(file_to_verify)
                        except HashError:
                            print(("Hash failure against index file %s. " +
                                   "Exiting program.") % file_to_verify)
                            sys.exit(1)
                else:
                    file_to_verify = decrypted_file
        except zipfile.BadZipFile:
            file_to_verify = decrypted_file

    if args.hmac:
        filehash = hmac_file(args.hmac.encode(), file_to_verify)
    else:
        filehash = hash_file(file_to_verify)

    if args.ID:
        print("Transaction provided, attempting to obtain hash from " +
              "blockchain")
        try:
            match = get_boc_hash(args.ID, filehash, args.chain, False)
        except (BOCError, HTTPError):
            print("Unable to find hash of file on the blockchain.")
            print("Filehash: %s" % filehash)
            print("Transaction ID: %s" % args.ID)
            sys.exit(1)
        if ('source_address' in match) and ('confirmations' in match):
            print(("Hash of local file %s matches hash placed on %s " +
                   "blockchain on %s UTC by %s with %d confirmation(s)")
                  % (file_to_verify, args.chain,
                  datetime.utcfromtimestamp(match['time'])
                  .strftime('%Y-%m-%d %H:%M:%S'),
                  match['source_address'], match['confirmations']))
        else:
            print(("Hash of local file %s matches hash in unconfirmed" +
                   " transaction on %s blockchain by %s")
                  % (file_to_verify, args.chain,
                     match['source_address']))
        sys.exit(0)
    # If no ID is provided, load the private key, get the address, and
    # look for any mutual exchanges.
    elif args.address:
        if (args.chain in ('BCH', 'tBCH')):
            try:
                provider_address = to_cash_address(args.address)
            except InvalidAddress:
                print(("Provided input could not be parsed as a BCH address:" +
                       " %s") % args.address)
                sys.exit(1)
        else:
            provider_address = args.address
    elif (not args.ID and not args.address):
        if args.chain not in ("BCH", "tBCH", "ETH", "tETH"):
            print("Searching for mutual exchanges not yet supported on %s",
                  args.chain)
            sys.exit(1)
        print("Searching for any address with mutual exchange ...")
        pairs_mutual = find_mutual(key.address, args.chain)
        provider_address = select_mutual(pairs_mutual)[0]
    else:
        print("Unexpected selection of arguments. Please view the help " +
              "dialog.")
        print(args)
        sys.exit(1)

    try:
        check_post_from_address(provider_address, args.chain, filehash,
                                file_to_verify, False, False)
    except ValueError as value_e:
        print(value_e)
        sys.exit(1)


if __name__ == "__main__":
    main()

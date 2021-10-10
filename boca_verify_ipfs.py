""" This script checks a BoCA post on a blockchain. The hash of the file
provided/index file, will be checked against a hash obtained from a
blockchain. The transaction ID can be given directly. Or an address can
be provided and the script will search all transactions for that
address. If neither is given, then it will check if there are addresses
that have a mutual exchange with the local wallet. If there is exactly
one, it will use that addres.
If there are multiple, it will give the user a choice.
Decryption uses the private key from the wallet.
This script obtains the data from the IPFS network, which means either
the IFPS hash needs to be provided or the transaction needs to use the
"getcid" option.
If the received data is a folder, an 'index.txt' will be searched for.
If found, all hashes contained within will be checked.
"""

import sys
import zipfile

from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path

from ipfshttpclient.exceptions import TimeoutError as IPFSTimeoutError
from cashaddress.convert import to_cash_address, InvalidAddress
from boca.blockchain import BOCError, check_post_from_address, find_mutual
from boca.blockchain import get_boc_hash, select_mutual, change_null
from boca.crypto import dec_file, hmac_file, key_manager, DecryptionError
from boca.ipfs import check_index, download_from_ipfs, hash_file, HashError
from boca.ipfs import unzip_file


def main():
    """ Download content from IPFS and verify it using a BoCA post.
    """
    parser = ArgumentParser(description="Verify data posted to the " +
                            "Blockchainusing Digital Forensics " +
                            "Chain-of-Custody.")
    parser.add_argument("--ID", help="Provide a transaction ID that has a " +
                        "posted hash.", type=str)
    parser.add_argument("--address", help="Provide an address that has one " +
                        "transaction with a posted hash.", type=str)
    parser.add_argument("--cid", help="Provide the IPFS CID to the content",
                        type=str)
    parser.add_argument("--keyfile", help="This file contains the encrypted " +
                        "private keys for accessing the blockchain(s).",
                        default="private.key")
    parser.add_argument("--dec", help="Use if the provided file was " +
                        "encrypted. An attempt will be made to decrypt.",
                        action="store_true")
    parser.add_argument("--chain", help="Specify which blockchain(s) to " +
                        "verify from (default is BCH)", default="BCH")
    parser.add_argument("--hmac", help="Calculate a HMAC of the file instead" +
                        " of a hash (requires a password).", type=str)
    parser.add_argument("--getcid", help="Attempt to get IPFS address from " +
                        "transaction, download data, and verify.",
                        action="store_true")

    args = parser.parse_args()
    args = change_null(args)

    # IPFS files are handled differently than getcid so we have to
    # overwrite that argument
    if (args.getcid and args.cid):
        print("Warning: getcid requires the --cid option not be used")
        args.cid = False

    # Only load the private keys if the 'dec' argument has been given or
    # there is no 'ID' and no 'address' or there is no path
    if (args.dec or not (args.ID or args.address)):
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
            print("Choose one of: BCH, tBCH, ETH")
            sys.exit(1)

    if args.cid:
        input_path = Path(args.cid)
        try:
            download_from_ipfs(input_path)
        except IPFSTimeoutError:
            print("Unable to download %s from IPFS" % input_path)
            print("Please make sure data is available on IPFS")
            sys.exit(1)
        if input_path.is_dir():
            file_to_verify = Path(args.cid, 'index.txt')
            try:
                check_index(file_to_verify)
            except HashError:
                print("Hash failure against index file %s. Exiting program."
                      % file_to_verify)
                sys.exit(1)
        else:
            args.path = Path(args.cid)
            file_to_verify = Path(args.cid)
    elif (args.cid and not args.getcid):
        print("The only way this code can run without a path is if the " +
              "'--getcid' option was used.")
        print("Attempting to find a transaction with IPFS CID included.")
        args.getcid = True

    if (args.dec and not args.getcid):
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

    # When using 'getcid' these values are initally set to '' as they
    # need to be obtained from the blockchain.
    if args.getcid:
        filehash = ''
        file_to_verify = ''
        file_to_decrypt = ''
    elif args.hmac:
        filehash = hmac_file(args.hmac.encode(), file_to_verify)
    else:
        filehash = hash_file(file_to_verify)

    # Process a transaction using 'getcid'
    if (args.ID and args.getcid):
        print("Transaction provided, attempting to obtain hash from " +
              "blockchain")
        try:
            match = get_boc_hash(args.ID, filehash, args.chain, args.getcid)
        except BOCError:
            print("Unable to find hash of file on the blockchain.")
            print("Filehash: %s" % filehash)
            sys.exit(1)
        ipfs_download = Path(match['ipfs_hash'])
        try:
            # Remove the leading "bitcoincash:" from the address if
            # necessary
            if ':' in match['source_address']:
                address_id = match['source_address'].split(':')[1]
            else:
                address_id = match['source_address']
            download_from_ipfs(ipfs_download, Path(address_id))
        except IPFSTimeoutError:
            print("Unable to download %s from IPFS" % ipfs_download)
            print("Please make sure data is available on IPFS")
            sys.exit(1)
        received_content = Path(address_id, ipfs_download)
        if (received_content.is_dir() and args.dec):
            print("Unable to decrypt folder %s. Please specify a file."
                  % received_content)
            sys.exit(1)
        elif args.dec:
            try:
                decrypted_file = dec_file(key, received_content, args.chain)
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
                        file_to_verify = Path(address_id, only_folder,
                                              'index.txt')
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
        elif (received_content.is_dir() and not args.dec):
            file_to_verify = Path(received_content, 'index.txt')
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
        else:
            # If none of the other clauses apply, then it was a file
            # posted to IPFS with no encryption
            file_to_verify = received_content
        filehash = hash_file(file_to_verify)
        try:
            match = get_boc_hash(args.ID, filehash, args.chain, False)
        except BOCError:
            print("Unable to find hash of file on the blockchain.")
            print("Filehash: %s" % filehash)
            sys.exit(1)
        if ('source_address' in match) and ('confirmations' in match):
            print(("Hash of local file %s matches hash placed on %s " +
                  "blockchain on %s UTC by %s with %d confirmation(s)")
                  % (file_to_verify, args.chain,
                  datetime.utcfromtimestamp(match['time'])
                  .strftime('%Y-%m-%d %H:%M:%S'),
                  match['source_address'], match['confirmations']))
        else:
            print(("Hash of local file %s matches hash in unconfirmed " +
                   "transaction on %s blockchain by %s")
                  % (file_to_verify, args.chain, match['source_address']))
        sys.exit(0)
    # Process a transaction not using 'getcid'
    elif (args.ID and not args.getcid):
        print("Transaction provided, attempting to obtain hash from " +
              "blockchain")
        try:
            match = get_boc_hash(args.ID, filehash, args.chain, args.getcid)
        except BOCError:
            print("Unable to find hash of file on the blockchain.")
            print("Filehash: %s" % filehash)
            sys.exit(1)
        if ('source_address' in match) and ('confirmations' in match):
            print(("Hash of local file %s matches hash placed on %s block" +
                   "chain on %s UTC by %s with %d confirmation(s)")
                  % (file_to_verify, args.chain,
                  datetime.utcfromtimestamp(match['time'])
                  .strftime('%Y-%m-%d %H:%M:%S'),
                  match['source_address'], match['confirmations']))
        else:
            print(("Hash of local file %s matches hash in unconfirmed " +
                   "transaction on %s blockchain by %s")
                  % (file_to_verify, args.chain, match['source_address']))
        sys.exit(0)
    # If no ID is provided, load the private key, get the address, and look
    # for any mutual exchanges.
    elif args.address:
        if (args.chain == 'BCH' or args.chain == 'tBCH'):
            try:
                provider_address = to_cash_address(args.address)
            except InvalidAddress:
                print("Provided input could not be parsed as a BCH address: %s"
                      % args.address)
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

    if (args.getcid and args.dec):
        check_post_from_address(provider_address, args.chain, filehash,
                                file_to_verify, args.getcid, key)
    elif (args.getcid and not args.dec):
        check_post_from_address(provider_address, args.chain, filehash,
                                file_to_verify, args.getcid, False)
    else:
        check_post_from_address(provider_address, args.chain, filehash,
                                file_to_verify, args.getcid, False)


if __name__ == "__main__":
    main()

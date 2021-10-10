"""This file will run indefinitely. It will create a list of mutual
exchange addresses. It will scan through all posts by the addresses,
looking for a '--postipfs' post. If it finds any, it will download from
IPFS and check, logging the results, and keeping a set of seen
transactions. It will sleep for 1 minute, and then look for any "new"
transactions by any of the addresses.
"""

import sys
import zipfile

from argparse import ArgumentParser
from pathlib import Path
from time import sleep
from ipfshttpclient.exceptions import TimeoutError as IPFSTimeoutError

from boca.blockchain import get_boc_hash, find_mutual
from boca.blockchain import BOCError, bch_get_version
from boca.blockchain import change_null, get_transactions_local
from boca.crypto import dec_file, key_manager, DecryptionError
from boca.ipfs import check_index, download_from_ipfs, hash_file, unzip_file
from boca.ipfs import HashError


def print_to_log(message, log_file):
    """Append a line to a log file

    :param message: The message to be appended.
    :type message: ``str``
    :param log_file: The log file to write the message to.
    :type log_file: ``Path``
    """

    with open(log_file, "a") as file_handle:
        message.rstrip()
        file_handle.write(message+"\n")
    return 0


def main():
    """Scan known addresses for any posts with IPFS cids. On finding
    any, download the content and verify.
    """
    parser = ArgumentParser(description="Scan the Blockchain for any posts " +
                            "using the Blockchain-of-Custody Application " +
                            "(BoCA).")
    parser.add_argument("--keyfile", help="This file contains the encrypted " +
                        "private keys for accessing the blockchain(s)",
                        default="private.key")
    parser.add_argument("--chain", help="Specify which blockchain(s) to post" +
                        " to (default is BCH).", default="BCH")
    parser.add_argument("--sleep", help="This is length of time to sleep in " +
                        "between scans for new posts (in seconds)", default=60)

    args = parser.parse_args()
    args = change_null(args)

    keys = key_manager(args.keyfile, args.chain)
    if args.chain == "BCH":
        print("Attempting to verify post to BCH blockchain")
        key = keys["BCH"]
    elif args.chain == "tBCH":
        print("Attempting to verify post to (testnet) BCH blockchain")
        key = keys["tBCH"]
    elif (args.chain == "ETH" or args.chain == "tETH"):
        print("Scanning is not yet supported on the ETH/tETH blockchain")
        sys.exit(0)
    else:
        print("Unknown blockchain: %s" % args.chain)
        print("Choose one of: BCH, tBCH, ETH, tETH")
        sys.exit(1)

    # Log for recording all valid posts
    log_verified = Path("scan_log_verified.txt")
    # Log for recording all invalid posts
    log_error = Path("scan_log_errors.txt")

    # Keep a track of which transactions have been "seen". These can
    # (and will) be ignored.
    seen_transactions = set()

    if log_verified.is_file():
        with open(log_verified, "r") as log_file:
            for line in log_file:
                seen_transactions.add(line.split(',')[0])

    if log_error.is_file():
        with open(log_error, "r") as log_file:
            for line in log_file:
                seen_transactions.add(line.split(',')[0])

    print("The following transactions have been previously processed and " +
          "will be ignored:")
    print(seen_transactions)

    print("Searching for any address with mutual exchange ...")
    pairs_mutual = find_mutual(key.address, args.chain)
    if len(pairs_mutual) == 0:
        print("No mutual exchanges found. Please exchange funds back and " +
              "forth with another address and retry.")
        sys.exit(1)

    print("Number of mutual exchange addresses found: %d" % len(pairs_mutual))

    # This code runs indefinitely
    while True:
        for current_match in pairs_mutual:
            current_address = current_match[0]
            try:
                ver = bch_get_version(current_address)
                if (ver == "main" and args.chain != "BCH"):
                    print("Incorrect network: " % ver)
                elif (ver == "test" and args.chain != "tBCH"):
                    print("Incorrect network: " % ver)
            except ValueError as val_e:
                print("%s is not a valid BCH mainnet/testnet address - %s" %
                      (current_address, val_e.args[0]))
                sys.exit(1)

            print("Searching for transactions involving: %s" % current_address)
            transactions = get_transactions_local(current_address, args.chain)

            # Any transactions that have been previously handled are
            # removed from the list
            for list_id, seen_tx in enumerate(seen_transactions):
                for tx_ in transactions:
                    if seen_tx == tx_['txid']:
                        transactions.remove(tx_)
            print("Number of unseen transactions: %d" % len(transactions))

            print("I have got as far as here in updating this code.")
            sys.exit(1)

            for tx_ in transactions:
                try:
                    match = get_boc_hash(tx_, '', args.chain, True)
                    match['file_hash'] = match['posted_data'].split(' ')[1]
                    ipfs_download = Path(match['ipfs_hash'])
                    address_id = current_address.split(':')[1]
                    try:
                        download_from_ipfs(ipfs_download, address_id)
                        file_to_decrypt = Path(address_id, ipfs_download)
                        if file_to_decrypt.is_dir():
                            print_to_log(tx_ + "," + str(ipfs_download) +
                                         ", IPFS content was a folder " +
                                         "instead of a file", log_error)
                            seen_transactions.add(tx_)
                        else:
                            try:
                                decrypted_file = dec_file(key, file_to_decrypt)
                            except DecryptionError as error:
                                print_to_log(tx_ + "," + str(ipfs_download) +
                                             ", Error with decryption: " +
                                             error.args[0], log_error)
                                seen_transactions.add(tx_)
                            except ValueError as error:
                                print_to_log(tx_ + "," + str(ipfs_download) +
                                             ", Error with decryption: " +
                                             error.args[0], log_error)
                                seen_transactions.add(tx_)
                            try:
                                output = unzip_file(decrypted_file)
                                if output == 0:
                                    file_to_verify = decrypted_file
                                else:
                                    if len(output) == 1:
                                        only_folder = Path(output.pop())
                                        file_to_verify = Path(only_folder,
                                                              'index.txt')
                                        if file_to_verify.is_file():
                                            try:
                                                check_index(file_to_verify)
                                            except HashError:
                                                print_to_log(
                                                    tx_ + "," +
                                                    str(ipfs_download) +
                                                    ", Hashes in index file " +
                                                    "did not match.",
                                                    log_error
                                                    )
                                                seen_transactions.add(tx_)
                                    else:
                                        file_to_verify = decrypted_file
                                if (match['file_hash'] ==
                                        hash_file(file_to_verify)):
                                    print_to_log(tx_ + "," +
                                                 str(ipfs_download) +
                                                 ", Valid file on blockchain",
                                                 log_verified)
                                    seen_transactions.add(tx_)
                                else:
                                    print_to_log(tx_ + "," +
                                                 str(ipfs_download) +
                                                 ", Hash of file not the "
                                                 "same as hash from " +
                                                 "blockchain", log_error)
                                    seen_transactions.add(tx_)
                            except zipfile.BadZipFile:
                                file_to_verify = decrypted_file
                    except IPFSTimeoutError:
                        print_to_log(tx_ + "," + str(ipfs_download) +
                                     ", Unable to download from IPFS",
                                     log_error)
                        seen_transactions.add(tx_)
                except BOCError:
                    print_to_log(tx_ + ",, Transaction is not of type " +
                                 "--postipfs", log_error)
                    seen_transactions.add(tx_)
        print("Sleeping for %d seconds." % args.sleep)
        sleep(args.sleep)


if __name__ == "__main__":
    main()

"""This script takes a file/folder and posts the hash to a blockchain.
The file can optionally be encrypted as well, but it is still the
plaintext file hash that gets posted to the blockchain.
The general format of posts will be:
bocf <hash of single file>
bocl <hash of list of files with details>
bocd <entire list posted directly> (future work)
bocs <string> (future work)
There is an interactive process for generating a list for bocl
"""

import sys
import zipfile

from argparse import ArgumentParser
from pathlib import Path

from boca.blockchain import find_mutual, select_mutual, send_memo, change_null
from boca.crypto import hmac_file, key_manager, enc_file
from boca.ipfs import zipdir, hash_file, parse_image_file


def main():
    """Post a hash of a document to a blockchain."""

    parser = ArgumentParser(description="Post data to a blockchain using the" +
                            " Blockchain-of-Custody Application (BoCA).")
    parser.add_argument("--path", help="This file will be hashed, and the " +
                        "hash posted to the blockchain. Note: this can also " +
                        "be a folder.", type=str)
    parser.add_argument("--enc", help="Set this flag if you wish to encrypt " +
                        "the file.", action="store_true")
    parser.add_argument("--keyfile", help="This file contains the encrypted " +
                        "private keys for accessing the blockchain(s).",
                        default="private.key")
    parser.add_argument("--balance", help="Get the balance of all accounts " +
                        "and exit", action="store_true")
    parser.add_argument("--chain", help="Specify which blockchain(s) to post" +
                        " to (default is BCH).", default="BCH")
    parser.add_argument("--hmac", help="Calculate a HMAC of the file instead" +
                        " of a hash (requires a password).", type=str)
    parser.add_argument("--imagefile", help="Obtain hashes from an image " +
                        "file and post these to the blockchain.", type=str)
    parser.add_argument("--selfenc", help="Set this flag to encrypt with " +
                        "your own public key.", action="store_true")

    args = parser.parse_args()
    args = change_null(args)

    if args.balance:
        key_manager(args.keyfile, 'ALL', True)
        sys.exit(0)

    keys = key_manager(args.keyfile, args.chain)
    string_to_post = "boc"

    if (not args.path) and (not args.imagefile):
        print("You must specify a file (or folder) to be posted.")
        print("Use the --path or --imagefile argument.")
        sys.exit(1)
    if (args.imagefile and args.enc):
        print("Encryption is not compatible with posting hashes from an " +
              "image file")
        sys.exit(1)

    # Using "--selfenc" implies "--enc"
    if (args.selfenc and not args.enc):
        args.enc = True

    if args.chain == "BCH":
        print("Attempting to post to BCH blockchain")
        key = keys["BCH"]
    elif args.chain == "tBCH":
        print("Attempting to post to (testnet) BCH blockchain")
        key = keys["tBCH"]
    elif args.chain == "ETH":
        print("Attempting to post to ETH blockchain")
        key = keys["ETH"]
    elif args.chain == "tETH":
        print("Attempting to post to (testnet) ETH blockchain")
        key = keys["ETH"]
    else:
        print("Unknown blockchain: %s" % args.chain)
        print("Choose one of: BCH, tBCH, ETH, tETH")
        sys.exit(1)

    if args.imagefile:
        found_hashes = parse_image_file(args.imagefile)
        if len(found_hashes) == 0:
            print("No hashes were found in %s" % args.imagefile)
            sys.exit(1)
        if len(found_hashes) == 1:
            print("Only a single hash found in %s" % args.imagefile)
            string_to_post = (string_to_post + "f" + " " +
                              found_hashes[0])  # "f" for file
            transaction_details = send_memo(key, string_to_post, args.chain)
            print("Transaction id: %s" % transaction_details['txid'])
            sys.exit(0)
        else:
            print("The following hashes were found in %s:" % args.imagefile)
            for i, found_hash in enumerate(found_hashes):
                print("%d. %s" % (i+1, found_hash))

            user_choice = -1
            while (user_choice < 0 or user_choice > len(found_hashes)+1):
                user_choice = int(input("Enter 0 if you do not wish to post " +
                                        "any hash.\n" +
                                        "Otherwise, enter [1-" +
                                        str(len(found_hashes)) +
                                        "] to post a single hash.\n" +
                                        "Or enter " +
                                        str(len(found_hashes)+1) +
                                        " to post all hashes: "
                                        ))
            if user_choice == 0:
                print("Exiting")
                sys.exit(0)
            elif user_choice == len(found_hashes)+1:
                print("Posting all hashes to the blockchain ...")
                print("Todo")
                sys.exit(0)
            else:
                print("Posting hash: %s to the blockchain" %
                      found_hashes[(user_choice-1)])
                string_to_post = (string_to_post + "f" + " " +  # "f"" for file
                                  found_hashes[(user_choice-1)])
                transaction_details = send_memo(key, string_to_post,
                                                args.chain)
                print("Transaction id: %s" % transaction_details['txid'])
                sys.exit(0)
    else:
        input_path = Path(args.path)

    if input_path.is_dir():
        # Need to create an index file and post the hash of the index
        # file to the Blockchain
        index_path = Path(input_path, 'index.txt')
        # Give the user the option to delete the existing index.txt file
        # if it is already there. If you use an old index.txt file and
        # add files to the folder, then they won't be hashed and put on
        # the blockchain.
        if index_path.is_file():
            print("Warning: There already exists an 'index.txt' file in %s."
                  % input_path)
            response = input("Do you wish to delete this file? (y/n): ")
            if response in ('Y', 'y'):
                print("Deleting file.")
                index_path.unlink()
            elif response in ('N', 'n'):
                print("Existing file will be used")
            else:
                print("Invalid input")
                sys.exit(1)
        if not index_path.is_file():
            with open(index_path, 'x', encoding="utf-8") as file_index:
                print("Please enter the following details: ")
                name = input("Name: ")
                description = input("Description of data: ")
                ref_no = input("Reference number: ")
                file_index.write("Blockchain-of-Custody Application Index\n")
                file_index.write("Name of data provider: %s\n" % name)
                file_index.write("Description of data: %s\n" % description)
                file_index.write("Reference number: %s\n" % ref_no)
                file_index.write("\nFiles: \n")
                for file in input_path.rglob("*"):
                    if (file != index_path and not file.is_dir()):
                        file_index.write("%s %s\n" % (hash_file(file),
                                         str(file)))
        file_to_post = index_path
        string_to_post = string_to_post + "l"  # "l" for list of files
        if args.enc:
            # Need to zip the folder, then encrypt
            file_to_encrypt = Path(input_path.parent, input_path.name + '.zip')
            if file_to_encrypt.is_file():
                print("Warning: There already exists an zip file %s."
                      % file_to_encrypt)
                response = input("Do you wish to delete this file? (y/n): ")
                if response in ('Y', 'y'):
                    print("Deleting file.")
                    file_to_encrypt.unlink()
                    with zipfile.ZipFile(file_to_encrypt, 'x',
                                         zipfile.ZIP_DEFLATED) as zipf:
                        zipdir(input_path, zipf)
                    print("Folder has been zipped (%s) and will be encrypted" %
                          file_to_encrypt)
                elif response in ('N', 'n'):
                    print("Existing file will be used")
                else:
                    print("Invalid input")
                    sys.exit(1)
            else:
                with zipfile.ZipFile(file_to_encrypt, 'x',
                                     zipfile.ZIP_DEFLATED) as zipf:
                    zipdir(input_path, zipf)
    else:
        # Process the file normally.
        file_to_post = input_path
        string_to_post = string_to_post + "f"  # "f" for file
        if args.enc:
            file_to_encrypt = input_path

    if args.hmac:
        filehash = hmac_file(args.hmac.encode(), file_to_post)
    else:
        filehash = hash_file(file_to_post)

    string_to_post = string_to_post + " " + filehash

    if args.enc:
        # Check to see if there is already an encrypted file
        already_encrypted = False
        existing_filename = Path(file_to_encrypt.parent,
                                 file_to_encrypt.name + '.enc')
        if existing_filename.is_file():
            print("Warning: There already exists an encrypted file: %s" %
                  existing_filename)
            response = input("Do you wish to delete this file? (y/n): ")
            if response in ('Y', 'y'):
                print("Deleting file.")
                existing_filename.unlink()
            elif response in ('N', 'n'):
                print("Existing file will be used")
                already_encrypted = True
            else:
                print("Invalid input")
                sys.exit(1)
        if not already_encrypted:
            if args.selfenc:
                mutual_key = key.public_key.hex()
            else:
                print("Searching for mutual exchanges ...")
                pairs_mutual = find_mutual(key.address, args.chain)
                print(pairs_mutual)
                mutual_key = select_mutual(pairs_mutual)[1]
            enc_filename = enc_file(mutual_key, file_to_encrypt)
            print("File encrypted as %s" % enc_filename)

    transaction_details = send_memo(key, string_to_post, args.chain)
    if transaction_details['status'] == 'failed':
        print("Unable to complete transaction.")
        print(f"Reason: {repr(transaction_details['error'])}")
    else:
        print("Transaction id: %s" % transaction_details['txid'])


if __name__ == "__main__":
    main()

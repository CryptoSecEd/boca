"""This script opens the stored private keys, decrypts with user
supplied password and sends an amount to an address. Can also just
query the balance for all addresses by not specifying either amount
nor address.
"""

import sys

from argparse import ArgumentParser
from bitcash.transaction import calc_txid
from bitcash.exceptions import InsufficientFunds

from boca.blockchain import get_balance_local, change_null, get_unspent_local
from boca.blockchain import broadcast_tx_local, spend_eth, spend_testnet_eth
from boca.crypto import key_manager, BCH_TO_SAT_MULTIPLIER


def main():
    """Send an amount of cryptocurrency to a specified address.
    """

    parser = ArgumentParser(description="Make a payment to an address. If " +
                            "you run the program without any amount or " +
                            "address, it will print the balance of the " +
                            "addresses.")
    parser.add_argument("--address", help="The destination address to send " +
                        "the payment.", type=str)
    parser.add_argument("--amount", help="The amount to send.", type=str)
    parser.add_argument("--chain", help="The blockchain to use for the " +
                        "payment (default is BCH)", default="BCH")
    parser.add_argument("--keyfile", help="This file contains the encrypted " +
                        "private keys for accessing the blockchain(s)",
                        default="private.key")
    parser.add_argument("--balance", help="Get the balance of all accounts " +
                        "and exit", action="store_true")

    args = parser.parse_args()
    args = change_null(args)

    if args.balance:
        key_manager(args.keyfile, 'ALL', True)
        sys.exit(0)

    if (not args.address and not args.amount):
        key_manager(args.keyfile, 'ALL', True)
        # Balance has already been printed, can exit.
        sys.exit(0)

    keys = key_manager(args.keyfile, args.chain)

    if not args.address:
        print("Please specify a destination address.")
        sys.exit(1)
    elif not args.amount:
        print("Please specify an amount to transfer.")
        sys.exit(1)

    if args.chain == 'BCH':
        if not keys["BCH"]:
            print("Cannot spend BCH as no such key in private key store")
            sys.exit(1)
        key = keys['BCH']
        key.unspents = get_unspent_local(key.address, args.chain)
        outputs = [(args.address, float(args.amount), "bch")]
        balance = get_balance_local(key.address, args.chain)
        print("BCH balance: %.8f BCH or %s satoshi" %
              (balance/BCH_TO_SAT_MULTIPLIER, balance))
        try:
            spend_tx = key.create_transaction(outputs, leftover=key.address)
            response = broadcast_tx_local(spend_tx, args.chain)
            if not response:
                raise ConnectionError("Unable to broadcast transaction")
        except ConnectionError as conn_e:
            print("Error Exception thrown in attempting to send BCH!", conn_e)
            sys.exit(1)
        except InsufficientFunds as insuff_e:
            print("Unable to execute transaction:")
            print(repr(insuff_e))
            sys.exit(1)
        print("Transaction ID: %s" % calc_txid(spend_tx))

    if args.chain == 'tBCH':
        if not keys["tBCH"]:
            print("Cannot spend (testnet) BCH as no such key in private key " +
                  "store")
            sys.exit(1)
        key = keys['tBCH']
        key.unspents = get_unspent_local(key.address, args.chain)
        outputs = [(args.address, float(args.amount), "bch")]
        balance = get_balance_local(key.address, args.chain)
        print("(testnet) BCH balance: %.8f BCH or %s satoshi" %
              (balance/BCH_TO_SAT_MULTIPLIER, balance))
        try:
            spend_tx = key.create_transaction(outputs, leftover=key.address)
            response = broadcast_tx_local(spend_tx, args.chain)
            if not response:
                raise ConnectionError("Unable to broadcast transaction")
        except ConnectionError as conn_e:
            print("Error Exception thrown in attempting to send (testnet) " +
                  "BCH!!", conn_e)
            sys.exit(1)
        except InsufficientFunds as insuff_e:
            print("Unable to execute transaction:")
            print(repr(insuff_e))
            sys.exit(1)
        print("Transaction ID: %s" % calc_txid(spend_tx))

    # Have not tested spending with ETH yet
    if args.chain == 'ETH':
        if not keys["ETH"]:
            print("Cannot spend ETH as no such key in private key store")
            sys.exit(1)
        key = keys['ETH']
        tx_ = spend_eth(key, args.address, args.amount)
        if tx_['status'] == 'failed':
            print("Unable to complete transaction. Reason: %s" % tx_['error'])
        else:
            print("Transaction ID: %s" % tx_['txid'])

    if args.chain == 'tETH':
        if not keys["ETH"]:
            print("Cannot spend (testnet) ETH as no such key in private key " +
                  "store")
            sys.exit(1)
        key = keys['ETH']
        tx_ = spend_testnet_eth(key, args.address, args.amount)
        if tx_['status'] == 'failed':
            print("Unable to complete transaction. Reason: %s" % tx_['error'])
            print(tx_)
        else:
            print("Transaction ID: %s" % tx_['txid'])


if __name__ == "__main__":
    main()

"""This contains all the blockchain related functions for BoCA
"""

import sys
import zipfile

from datetime import datetime
from decimal import Decimal
from pathlib import Path
from secrets import token_bytes
from time import sleep

from hexbytes import HexBytes
from eth_account import account
from eth_account._utils.signing import to_standard_v
from eth_account._utils.legacy_transactions import \
    serializable_unsigned_transaction_from_dict
from eth_keys.datatypes import Signature
from eth_utils import to_checksum_address
from bitcash.cashaddress import Address
from bitcash.format import public_key_to_address
from bitcash.network.meta import Unspent
from bitcash.transaction import calc_txid, get_op_pushdata_code
from bitcash.utils import bytes_to_hex, hex_to_bytes
from bitcash.wallet import PrivateKeyTestnet, PrivateKey
from ipfshttpclient.exceptions import TimeoutError as IPFSTimeoutError
from web3 import Web3
from web3.exceptions import TransactionNotFound

import requests
import boca


BCH_OP_RETURN_LIMIT = 220
DEFAULT_TIMEOUT = 30
DEBUG = False
FULLSTACK_LIMIT = 20
ETHERSCAN_URL_MAINNET = "https://api.etherscan.io"
ETHERSCAN_URL_TESTNET = "https://api-ropsten.etherscan.io"
MAX_PRIORITY_FEE_PER_GAS_TEST = 1000000000
MAX_PRIORITY_FEE_PER_GAS_MAIN = 1000000000


class BOCError(Exception):
    """ Raised whenever a transaction does not have appropriate boca data
    """


def bch_get_version(address_string):
    """Determine if the provided BCH address is main or testnet

    :param address_string: The address to be tested
    :type address_string: ``str``
    :raises ValueError: If the address is not BCH/tBCH address
    :rtype: ``str``
    """
    address = Address.from_string(address_string)
    if address.prefix == "bchtest":
        chain = "test"
    elif address.prefix == "bitcoincash":
        chain = "main"
    else:
        raise(ValueError("Address format unrecognised or unsupported: %s"
              % address_string))
    return chain


def broadcast_tx_local(memo, chain):
    """Broadcast a BCH/tBCH transaction using the Bitcore.io REST API

    :param memo: The raw transaction to be posted to the blockchain
    :type memo: ``str``
    :param chain: Which chain to post to: BCH or tBCH
    :type chain: ``str``
    :raises ValueError: If a chain other than BCH/tBCH is provided
    :rtype: ``bool``
    """
    if chain == "BCH":
        api_url = "https://api.bitcore.io/api/BCH/mainnet/tx/send"
        network = "mainnet"
    elif chain == "tBCH":
        api_url = "https://api.bitcore.io/api/BCH/testnet/tx/send"
        network = "testnet"
    else:
        raise ValueError("Chain not yet supported: %s" % chain)
    request = requests.post(
        api_url,
        json={"rawTx": memo, "network": network, "coin": "BCH"},
        timeout=DEFAULT_TIMEOUT,
    )
    request.raise_for_status()
    return bool(request.status_code == 200)


def change_null(args):
    """ This function changes all missing arguments to "False" instead
    of "None"

    :param args: The arguments passed when executing the code.
    :type args: ``argparse.Namespace``
    :rtype: ``argparse.Namespace``
    """
    for arg in vars(args):
        if getattr(args, arg) is None:
            setattr(args, arg, False)
    return args


def check_post_from_address(provider_address, chain, filehash,
                            file_to_verify, getcid, key):
    """ Find all posts by an address that have a BoCA post matching a
    filehash.

    :param provider_address: Address to check
    :type provider_address: ``str``
    :param chain: The blockchain to query
    :type chain: ``str``
    :param filehash: The filehash in hex
    :type filehash: ``str``
    :param file_to_verify: The name of the file being checked
    :type file_to_verify: ``pathlib.Path``
    :param getcid: If this flag is set, then it attempts to get the IPFS
    cid from the blockchain post, download, and verify.
    :type getcid: ``bool``
    :param key: The private key that may be needed to decrypt.
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet``
    :raises ValueError: If an unsupported chain is queried.
    :rtype: ``int``
    """
    if chain in ('BCH', 'tBCH'):
        check_post_from_address_bch(provider_address, chain, filehash,
                                    file_to_verify, getcid, key)
    elif chain == 'tETH':
        check_post_from_address_eth(provider_address, chain, filehash,
                                    file_to_verify, getcid, key)
    else:
        raise ValueError(("Chain %s not supported in check_post_from_" +
                          "address()") % chain)
    return 0


def check_post_from_address_bch(provider_address, chain, filehash,
                                file_to_verify, getcid, key):
    """ Find all posts by an address that have a BoCA post matching a
    filehash in the BCH/tBCH blockchain.

    :param provider_address: Address to check
    :type provider_address: ``str``
    :param chain: The blockchain to query (should be either BCH or tBCH)
    :type chain: ``str``
    :param filehash: The filehash in hex
    :type filehash: ``str``
    :param file_to_verify: The name of the file being checked
    :type file_to_verify: ``pathlib.Path``
    :param getcid: If this flag is set, then it attempts to get the IPFS
    cid from the blockchain post, download, and verify.
    :type getcid: ``bool``
    :param key: The private key that may be needed to decrypt.
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet``
    :raises ValueError: If an unsupported chain is queried.
    :rtype: ``int``
    """
    try:
        ver = bch_get_version(provider_address)
    except ValueError as exc:
        print("%s is not a valid BCH mainnet/testnet address - %s"
              % (provider_address, exc.args[0]))
        sys.exit(1)
    if ver == 'main' and chain == 'tBCH':
        print("Error: chain specified %s but address is format %s"
              % (chain, ver))
        sys.exit(1)
    elif ver == 'test' and chain == 'BCH':
        print("Error: chain specified %s but address is format %s"
              % (chain, ver))
        sys.exit(1)
    elif ((ver == 'test' and chain == 'tBCH') or
          (ver == 'main' and chain == 'BCH')):
        if getcid:
            search_address_getcid(provider_address, filehash, chain, key)
        else:
            all_matches = search_address(provider_address, filehash, chain)
            for match in all_matches:
                if ('source_address' in match) and ('confirmations' in match):
                    print(("Hash of local file %s matches hash placed on %s " +
                           "blockchain on %s UTC by %s with %d confirmation" +
                           "(s) with TXID %s")
                          % (file_to_verify, chain,
                          datetime.utcfromtimestamp(match['time'])
                                  .strftime('%Y-%m-%d %H:%M:%S'),
                          match['source_address'], match['confirmations'],
                          match['txid']))
                else:
                    print(("Hash of local file %s matches hash in unconfirme" +
                           "d transaction on %s blockchain by %s with TXID %s")
                          % (file_to_verify, chain, match['source_address'],
                             match['txid']))
            if len(all_matches) == 0:
                print("No matching hash posted by the provided address found" +
                      " on the blockchain.")
            sys.exit(0)
    else:
        raise ValueError("Address format unrecognised or unsupported: %s"
                         % provider_address)


def check_post_from_address_eth(provider_address, chain, filehash,
                                file_to_verify, getcid, key):
    """Placeholder for function (not implemented yet, may not be
    possible). It would find all posts by an address that have a BoCA
    post matching a filehash in the ETH/tETH blockchain.
    """

    if getcid:
        search_address_getcid(provider_address, filehash, chain, key)
    else:
        all_matches = search_address(provider_address, filehash, chain)
        for match in all_matches:
            post_time = datetime.utcfromtimestamp(match['time'])\
                            .strftime('%Y-%m-%d %H:%M:%S')
            print(f"Hash of file {file_to_verify} matches hash placed on " +
                  f"{chain} blockchain on {post_time} by " +
                  f"{match['source_address']} with {match['confirmations']}" +
                  f" confirmation(s) with TXID {match['txid']}")
        if len(all_matches) == 0:
            print("No matching hash posted by the provided address found" +
                  " on the blockchain.")
        sys.exit(0)


def find_mutual(key_address, chain):
    """For the given (t)BCH address (A), find all addresses B such that
    there are transactions going both directions: A-> B and B-> A
    At the moment, it only checks BCH/tBCH, but we need to be able to
    check others based on args.chain

    :param key_address: Address to check for exchanges
    :type provider_address: ``str``
    :param chain: The blockchain to query (should be either BCH or tBCH)
    :type chain: ``str``
    :raises ConnectionError: If it cannot get the transactions
    :raises ValueError: If unsupported chain requested
    :returns: A list of tuples containing (B addr, B public key, A addr)
    :rtype: ``list``
    """
    #
    if chain in ("BCH", "tBCH"):
        return find_mutual_bch(key_address, chain)
    if chain in ("ETH", "tETH"):
        return find_mutual_eth(key_address, chain)
    raise ValueError(f"Chain not yet supported: {chain}")


def find_mutual_bch(key_address, chain):
    """For the given (t)BCH address (A), find all addresses B such that
    there are transactions going both directions: A-> B and B-> A

    :param key_address: Address to check for exchanges
    :type provider_address: ``str``
    :param chain: The blockchain to query (should be either BCH or tBCH)
    :type chain: ``str``
    :raises ConnectionError: If it cannot get the transactions
    :raises ValueError: If unsupported chain requested
    :returns: A list of tuples containing (B addr, B public key, A addr)
    :rtype: ``list``
    """
    #
    try:
        if chain in ("BCH", "tBCH"):
            transactions = get_transactions_local(key_address, chain)
        else:
            print("Chain not yet supported")
            sys.exit(1)
    except ConnectionError:
        print("The details for the address could not be obtained. %s"
              % (key_address))
        print("Please check the address, or wait for confirmation, or try " +
              "later in case the API server is currently overloaded).")
        sys.exit(1)
    pairs_unique = set()
    if chain == "BCH":
        version = "main"
    elif chain == "tBCH":
        version = "test"
    else:
        raise ValueError("Chain not supported in find_mutual(): %s" % chain)
    # For every transaction found, extract a tuple comprising of:
    # (paying cashAddr, paying public key, receiving cashAddr)
    for txn in transactions:
        raw_tx = txn['details']
        for txin in raw_tx['vin']:
            sender_pk = txin['scriptSig']['asm'].split(' ')[1]
            addr1 = public_key_to_address(bytes.fromhex(sender_pk), version)
            for txout in raw_tx['vout']:
                if 'addresses' in txout['scriptPubKey']:
                    for addr2 in txout['scriptPubKey']['addresses']:
                        pairs_unique.add((addr1, sender_pk, addr2))
    # Using a set to remove duplicates, but the returned value is
    # converted to a list.
    pairs_mutual = set()
    for pair1 in pairs_unique:
        for pair2 in pairs_unique:
            if ((pair1[0] == pair2[2]) and (pair1[2] == pair2[0])
                    and (pair1[0] != pair1[2]) and (pair1[2] == key_address)):
                pairs_mutual.add(pair1)
    # The returned tuple will always have the input address as the third
    # entry
    return list(pairs_mutual)


def find_mutual_eth(key_address, chain):
    """For the given (t)ETH address (A), find all addresses B such that
    there are transactions going both directions: A-> B and B-> A

    :param key_address: Address to check for exchanges
    :type provider_address: ``str``
    :param chain: The blockchain to query (should be either BCH or tBCH)
    :type chain: ``str``
    :raises ConnectionError: If it cannot get the transactions
    :raises ValueError: If unsupported chain requested
    :returns: A list of tuples containing (B addr, B public key, A addr)
    :rtype: ``list``
    """
    #
    try:
        if chain in ("ETH", "tETH"):
            transactions = get_eth_transactions(key_address, chain)
        else:
            print("Chain not yet supported")
            sys.exit(1)
    except ConnectionError:
        print("The details for the address could not be obtained. %s"
              % (key_address))
        print("Please check the address, or wait for confirmation, or try " +
              "later in case the API server is currently overloaded).")
        sys.exit(1)

    pairs_unique = set()

    for transaction in transactions:
        addr1 = to_checksum_address(transaction['from'])
        addr2 = to_checksum_address(transaction['to'])
        txid = transaction['hash']
        try:
            sender_pubkey = pub_key_from_tx_eth(txid, chain)
            pairs_unique.add((addr1, sender_pubkey, addr2))
        except ValueError:
            print(f"Unable to obtain public key from: {txid}")
    # Using a set to remove duplicates, but the returned value is
    # converted to a list.
    pairs_mutual = set()
    for pair1 in pairs_unique:
        for pair2 in pairs_unique:
            if ((pair1[0] == pair2[2]) and (pair1[2] == pair2[0])
                    and (pair1[0] != pair1[2]) and (pair1[2] == key_address)):
                pairs_mutual.add(pair1)
    # The returned tuple will always have the input address as the third
    # entry
    return list(pairs_mutual)


def gen_tbch():
    """Generate a (testnet) BCH Private key

    :returns: A testnet BCH private key
    :rtype: ``bitcash.wallet.PrivateKeyTestnet``
    """
    key = PrivateKeyTestnet()
    print("(testnet) BCH Address is: %s" % key.address)
    return key.to_wif()


def gen_bch():
    """Generate a BCH Private key

    :returns: A BCH private key
    :rtype: ``bitcash.wallet.PrivateKey``
    """
    key = PrivateKey()
    print("BCH Address is: %s" % key.address)
    return key.to_wif()


def gen_eth():
    """Generate an Ethereum Private key

    :returns: An Ethereum private key (in hex)
    :rtype: ``str``
    """
    key = token_bytes(32)
    acct = account.Account.from_key(key)
    print("ETH Address is: %s" % acct.address)
    return key.hex()


def get_balance_local(address, chain):
    """Gets the balance of any testnet/mainnet BCH address using the
    fullstack.cash Rest API

    :param address: Address to query
    :type address: ``str``
    :param chain: Blockchain to query
    :type chain: ``str``
    :raises ValueError: If unsupported chain requested or if unable to
    query the API.
    :returns: The balance of the address (including unconfirmed)
    :rtype: ``float''
    """
    if chain == "tBCH":
        endpoint = 'https://testnet3.fullstack.cash/v5/electrumx/balance/{}'
    elif chain == "BCH":
        endpoint = 'https://api.fullstack.cash/v5/electrumx/balance/{}'
    else:
        raise ValueError("Invalid input in get_balance_local: " + chain)

    request = requests.get(endpoint.format(address), timeout=DEFAULT_TIMEOUT)
    request.raise_for_status()  # pragma: no cover
    response = request.json()
    if response['success'] is not True:
        print(response)
        raise ValueError('Unable to get address balance: ' + address)
    return response['balance']['confirmed']+response['balance']['unconfirmed']


def get_boc_hash(transaction, filehash, chain, getcid):
    """Checks to see if a transaction has a BoCA post of the provided
    file hash

    :param tx: Transaction ID or dictionary of raw transaciton details
    :type tx: ``str`` or ``dict``
    :param filehash: Hash of file to check for
    :type filehash: ``str``
    :param chain: Blockchain to query
    :type chain: ``str``
    :param getcid: If this flag is set then just get the IPFS CID
    :type getcid: ``bool``
    :returns: Dictionary with source_address, posted_data, time, and
    confirmations.
    :rtype: ``dict``
    """
    if chain in ('BCH', 'tBCH'):
        return get_boc_hash_bch(transaction, filehash, chain, getcid)
    if chain == 'tETH':
        return get_boc_hash_eth(transaction, filehash, chain, getcid)
    if chain == 'ETH':
        return get_boc_hash_eth(transaction, filehash, chain, getcid)
    print("Chain %s not yet supported in get_boc_hash()" % chain)
    sys.exit(1)


def get_boc_hash_bch(tx_in, filehash, chain, getcid):
    """Checks to see if a BCH transaction has a BoCA post of the
    provided file hash on either the BCH or testnet BCH blockchain

    :param tx_in: Transaction ID or dictionary of raw transaciton details
    :type tx_in: ``str`` or ``dict``
    :param filehash: Hash of file to check for
    :type filehash: ``str``
    :param chain: Blockchain to query
    :type chain: ``str``
    :param getcid: If this flag is set then just get the IPFS CID
    :type getcid: ``bool``
    :returns: Dictionary with source_address, posted_data, time, and
    confirmations.
    :rtype: ``dict``
    """
    # The function will get the tx details if provided a tx ID,
    # otherwise will use the values in the dictionary.
    if isinstance(tx_in, str):
        transaction = get_raw_transaction(tx_in, chain)
    elif isinstance(tx_in, dict):
        transaction = tx_in['details']
    else:
        raise(ValueError("Invalid type for tx input in get_boc_hash_bch(): %s"
              % type(tx_in)))
    output = {}
    for txout in transaction['vout']:
        # print("txout: %s" % txout)
        if "cashAddrs" in txout['scriptPubKey']:
            output['source_address'] = txout['scriptPubKey']['cashAddrs'][0]
        elif "addresses" in txout['scriptPubKey']:
            output['source_address'] = txout['scriptPubKey']['addresses'][0]
        assembly = txout['scriptPubKey']['asm'].split(' ')
        if (assembly[0] == "OP_RETURN") and (assembly[1] == "621"):
            output['posted_data'] = hex_to_bytes(assembly[2]).decode("utf-8")
    if 'posted_data' not in output:
        # print("No memo.cash post found in transaction %s" % tx_id)
        raise BOCError
    split_post = output['posted_data'].split(' ')
    if getcid is False:
        header = split_post[0]
        boc_hash = split_post[1]
        # print(boc_hash+" "+filehash)
    elif (getcid is True and len(split_post) == 3):
        header = split_post[0]
        boc_hash = split_post[1]
        output['ipfs_hash'] = split_post[2]
        return output
    else:
        # If getcid is used, we ignore any transactions that don't
        # have a third argument
        raise BOCError
    if header in ("bocf", "bocl"):
        # bocf - hash of file, bocl - hash of index file
        # Regardless of the type, the same details are returned
        if boc_hash == filehash:
            # A transaction only has 'time' after confirmation
            if 'time' in transaction:
                output['time'] = transaction['time']
            if 'confirmations' in transaction:
                output['confirmations'] = transaction['confirmations']
            return output
    elif header == "bocd":
        # These types of posts are not yet supported
        pass
    else:
        # Ignore invalid posts
        pass
    # If have not returned by this point, raise BOCError
    raise BOCError


def get_boc_hash_eth(transaction, filehash, chain, getcid):
    """Checks to see if a ETH transaction has a BoCA post of the
    provided file hash on either the BCH or testnet BCH blockchain

    :param transaction: Transaction ID or dictionary of raw transaciton
    details
    :type transaction: ``str`` or ``dict``
    :param filehash: Hash of file to check for
    :type filehash: ``str``
    :param chain: Blockchain to query
    :type chain: ``str``
    :param getcid: If this flag is set then just get the IPFS CID
    :type getcid: ``bool``
    :returns: Dictionary with source_address, posted_data, time, and
    confirmations.
    :rtype: ``dict``
    """
    from boca.config import INFURA_URL_MAINNET

    if chain == 'ETH':
        output = {}
        w3main = Web3(Web3.HTTPProvider(INFURA_URL_MAINNET))
        transaction = w3main.eth.getTransaction(transaction)

        if 'input' not in transaction:
            print("No input data in %s" % transaction)
            raise BOCError
        output['posted_data'] = (hex_to_bytes(transaction['input'][2:])
                                 .decode("utf-8"))
        split_post = output['posted_data'].split(' ')
        if len(split_post) == 1:
            raise BOCError(f"No BoCA data in ETH transaction: {transaction}")
        header = split_post[0]
        boc_hash = split_post[1]
        if getcid is True:
            if len(split_post) == 3:
                output['ipfs_hash'] = split_post[2]
                output['source_address'] = transaction['from']
                return output
            # If getcid is used, we ignore any transactions that don't
            # have a third argument
            raise BOCError
        if header in ("bocf", "bocl"):
            if boc_hash == filehash:
                output['confirmations'] = w3main.eth.blockNumber -\
                    transaction['blockNumber']
                output['source_address'] = transaction['from']
                output['time'] = w3main.eth.\
                    getBlock(transaction['blockNumber'])['timestamp']
            return output
        if header == "bocd":
            # These types of posts are not yet supported
            pass
        else:
            # Ignore invalid posts
            pass
    elif chain == 'tETH':
        output = {}
        w3test = Web3(Web3.HTTPProvider(boca.config.INFURA_URL_TESTNET))
        transaction = w3test.eth.getTransaction(transaction)

        if 'input' not in transaction:
            print("No input data in %s" % transaction)
            raise BOCError
        output['posted_data'] = (hex_to_bytes(transaction['input'][2:])
                                 .decode("utf-8"))
        split_post = output['posted_data'].split(' ')
        if len(split_post) == 1:
            raise BOCError("No BoCA data in (testnet) ETH transaction: " +
                           f"{transaction}")
        header = split_post[0]
        boc_hash = split_post[1]
        if getcid is True:
            if len(split_post) == 3:
                output['ipfs_hash'] = split_post[2]
                output['source_address'] = transaction['from']
                return output
            # If getcid is used, we ignore any transactions that don't
            # have a third argument
            raise BOCError
        if header in ("bocf", "bocl"):
            if boc_hash == filehash:
                output['confirmations'] = w3test.eth.blockNumber -\
                    transaction['blockNumber']
                output['source_address'] = transaction['from']
                output['time'] = w3test.eth\
                    .getBlock(transaction['blockNumber'])['timestamp']
                return output
            raise BOCError
        if header == "bocd":
            # These types of posts are not yet supported
            pass
        else:
            # Ignore invalid posts
            pass
    # If have not returned by this point, raise BOCError
    raise BOCError


def get_eth_transactions(address, chain):
    """Get all ETH/tETH transactions for a given address

    :param address: The desired address to query
    :type address: ``str``
    :param chain: The chain to query
    :type chain: ``str``
    :raises ValueError: If an invalid chain is requested or unable to
    query the endpoint
    :returns: Transaction details
    :rtype: ``list``
    """
    from boca.config import ETHERSCAN_API_KEY
    if chain == "ETH":
        endpoint = (ETHERSCAN_URL_MAINNET + "/api?module=account&" +
                    "action=txlist&address={}&sort=asc&apikey=" +
                    ETHERSCAN_API_KEY)
    elif chain == "tETH":
        endpoint = (ETHERSCAN_URL_TESTNET + "/api?module=account&" +
                    "action=txlist&address={}&sort=asc&apikey=" +
                    ETHERSCAN_API_KEY)
    headers = {'User-Agent': 'Mozilla/5.0 '}
    request = requests.get(endpoint.format(address), headers=headers,
                           timeout=DEFAULT_TIMEOUT)
    request.raise_for_status()
    response = request.json(parse_float=Decimal)
    if not (int(response["status"]) == 1 and response["message"] == "OK"):
        raise ValueError(f"Unable to get transactions for address {address}")
    # For some reason, the API is has repetitions. The following removes
    # them.
    output = []
    [output.append(x) for x in response["result"] if x not in output]
    return output


def get_raw_transaction(txid, chain):
    """Get a single raw BCH transaction using fullstack.cash

    :param txid: The desired transaction ID
    :type txid: ``str``
    :param chain: The chain to query
    :type chain: ``str``
    :raises ValueError: If chain value is invalid or API request fails
    :returns: JSON dictionary of raw transaction details
    :rtype: ``dict``
    """
    if chain == "tBCH":
        endpoint = 'https://testnet3.fullstack.cash/v5/electrumx/tx/data/{}'
    elif chain == "BCH":
        endpoint = 'https://api.fullstack.cash/v5/electrumx/tx/data/{}'
    else:
        raise ValueError("Invalid input in get_raw_transaction(): " + chain)

    request = requests.get(endpoint.format(txid), timeout=DEFAULT_TIMEOUT)
    request.raise_for_status()  # pragma: no cover
    response = request.json(parse_float=Decimal)
    if response['success'] is not True:
        print(response)
        raise ValueError('Unable to get transaction details ' + txid)
    return response['details']


# Fullstack has a limit of 20 transaction ids per call,
# So this function will return the output of one call
def get_single_batch_transactions(txids, endpoint):
    """Send a request to Fullstack.cash for transaction details (not
    going over the limit).

    :param txids: List of transaction IDs
    :type txids: ``list``
    :param endpoint: The REST API endpoint to send the request
    :type endpoint: ``str``
    :raises ValueError: If txids has too many txids or unable to query
    the endpoint
    :returns: Transaction details
    :rtype: ``dict``
    """

    if len(txids) > FULLSTACK_LIMIT:
        raise ValueError('Too many transactions for Fullstack API: ' + txids)
    raw_txs_api = endpoint + 'tx/data'
    request = requests.post(raw_txs_api, json={"txids": txids},
                            timeout=DEFAULT_TIMEOUT)
    request.raise_for_status()
    response = request.json(parse_float=Decimal)
    if response['success'] is not True:
        print(response)
        raise ValueError('Unable to get transactions details ' + txids)
    return response['transactions']


def get_transactions_local(address, chain):
    """Get details of all transactions by a given address. It only
    requests FULLSTACK_LIMIT transactions at a time due to the limit.

    :param address: The address to query
    :type address: ``str``
    :param chain: The blockchain to query
    :param chain: ``str```
    :raises ValueError: If an invalid chain is requested or unable to
    query the endpoint
    :returns: Transaction details
    :rtype: ``list``
    """

    if chain == "tBCH":
        endpoint = 'https://testnet3.fullstack.cash/v5/electrumx/'
    elif chain == "BCH":
        endpoint = 'https://api.fullstack.cash/v5/electrumx/'
    else:
        raise ValueError("Invalid input in get_transactions_local(): " + chain)

    txs_api = endpoint + 'transactions/{}'
    request = requests.get(txs_api.format(address), timeout=DEFAULT_TIMEOUT)

    request.raise_for_status()  # pragma: no cover
    response = request.json(parse_float=Decimal)
    if response['success'] is not True:
        print(response)
        raise ValueError('Unable to get transactions for address: ' + address)
    all_txs = []
    while len(response['transactions']) > 0:
        txids = []
        while (len(response['transactions']) > 0 and
               len(txids) != FULLSTACK_LIMIT):
            single_tx = response['transactions'].pop(0)
            txids.append(single_tx['tx_hash'])
        # print(get_single_batch_transactions(txids, endpoint))
        all_txs = all_txs + get_single_batch_transactions(txids, endpoint)
    return all_txs


def get_unspent_local(address, chain):
    """Get all UTXOs for an address using the Fullstack.cash API
    Formly used bitcore.io but it couldn't handle unconfirmed
    transactions with UTXOs

    :param address: Address to query
    :type address: ``str```
    :param chain: Chain to query
    :type chain: ``str``
    :raises ValueError: If invalid chain requested or unable to get
    response from API
    :returns: List of bitcash.network.meta.Unspent
    :rtype: ``list``
    """
    if ":" in address:
        address = address.split(":")[1]
    if chain == "BCH":
        api = "https://api.fullstack.cash/v5/electrumx/utxos/{}"
    elif chain == "tBCH":
        api = "https://testnet3.fullstack.cash/v5/electrumx/utxos/{}"
    else:
        raise ValueError("Invalid input in get_unspent_local(): " + chain)
    request = requests.get(api.format(address), timeout=DEFAULT_TIMEOUT)
    request.raise_for_status()
    if request.json()['success'] is not True:
        raise ValueError("Unable to obtain unspent for address: %s" % address)
    unspents = []
    for transaction in request.json()['utxos']:
        amount = transaction['value']
        vout = transaction['tx_pos']
        full_tx = get_raw_transaction(transaction['tx_hash'], chain)
        if 'confirmations' in full_tx:
            confirmations = full_tx['confirmations']
        else:
            confirmations = 0
        script = full_tx['vout'][vout]['scriptPubKey']['hex']
        unspents.append(
            Unspent(
                amount,
                confirmations,
                script,
                transaction['tx_hash'],
                vout,
            )
        )
    return unspents


def parse_cryptoapis_raw(response):
    """Parse the response from cryptoapis.io so it has a structure
    similar to other apis.
    I stopped using this API as it required throttling requests

    :param response: Transaction details provided by cryptoapis.io
    :type response: ``dict``
    :returns: Transaction formated to be consistent with other APIs
    :rtype: ``dict``
    """
    response['vin'] = response.pop('txins')
    response['vout'] = response.pop('txouts')
    if 'timestamp' not in response:
        # Later, I may want to code a way to continue if it is not
        # confirmed. Exit for now.
        print('Transaction is not yet confirmed, please try later')
        sys.exit(1)
    response['time'] = response.pop('timestamp')
    response['blocktime'] = response['time']
    value_in = 0
    for txin in response['vin']:
        value_in += float(txin['amount'])
        txin['value'] = txin.pop('amount')
        txin['scriptSig'] = txin.pop('script')
        txin['txid'] = txin.pop('txout')
        if len(txin['addresses']) != 1:
            print("Expected only a single address in response[vin][addresses]")
            sys.exit(1)
        txin['cashAddress'] = txin.pop('addresses')[0]
    response['valueIn'] = value_in
    value_out = 0
    for txout in response['vout']:
        value_out += float(txout['amount'])
        txout['value'] = txout.pop('amount')
        if txout['type'] == 'pubkeyhash':
            txout['script']['cashAddrs'] = txout.pop('addresses')
        txout['scriptPubKey'] = txout.pop('script')
    response['valueOut'] = value_out
    response['fees'] = float(response.pop('fee'))
    return response


def pub_key_from_tx_eth(txid, chain):
    """Obtain the public key from an Ethereum transaction
    """
    from boca.config import INFURA_URL_MAINNET, INFURA_URL_TESTNET
    if chain == "ETH":
        w3main = Web3(Web3.HTTPProvider(INFURA_URL_MAINNET))
        transaction = w3main.eth.get_transaction(txid)
    elif chain == "tETH":
        w3test = Web3(Web3.HTTPProvider(INFURA_URL_TESTNET))
        transaction = w3test.eth.get_transaction(txid)
    vrs = (to_standard_v(transaction['v']),
           int.from_bytes(transaction['r'], "big"),
           int.from_bytes(transaction['s'], "big"))
    signature = Signature(vrs=vrs)
    tx_dict = {
               'nonce': transaction.nonce,
               'gasPrice': transaction.gasPrice,
               'gas': transaction.gas,
               'to': transaction.to,
               'value': transaction.value
              }
    if chain == "ETH":
        tx_dict['chainId'] = "0x01"
    elif chain == "tETH":
        tx_dict['chainId'] = "0x03"
    if 'input' in transaction:
        tx_dict['data'] = transaction['input']
    serialized_tx = serializable_unsigned_transaction_from_dict(tx_dict)
    rec_pub = signature.recover_public_key_from_msg_hash(serialized_tx.hash())

    if rec_pub.to_checksum_address() != transaction['from']:
        raise ValueError("Unable to obtain public key from transaction: " +
                         f"{txid}")
    # I'm returning the key in this format to be consistent with the BCH
    # format.
    return rec_pub.to_compressed_bytes().hex()


def search_address(address, filehash, chain):
    """Search all transactions by the provided address and finds all
    that have a BoCA post with the matching file hash

    :param address: The address to query
    :type address: ``str``
    :param filehash: The filehash to look for
    :type filehash: ``str``
    :param chain: The blockchain to query
    :type chain: ``str``
    :returns: A list of all transactions with BoCA post matching the
    filehash
    :rtype: ``list``
    """

    print(f"Searching for transactions involving {address}")
    if chain in ('BCH', 'tBCH'):
        transactions = get_transactions_local(address, chain)
        outputs = []
        for transaction in transactions:
            try:
                output = get_boc_hash(transaction, filehash, chain, False)
                if output['source_address'] == address:
                    output['txid'] = transaction['details']['txid']
                    outputs.append(output)
            except BOCError:
                # Ignore transactions without a BOC post
                pass
        return outputs
    if chain in ('ETH', 'tETH'):
        transactions = get_eth_transactions(address, chain)
        outputs = []
        for transaction in transactions:
            try:
                output = get_boc_hash(transaction['hash'], filehash, chain,
                                      False)
                if ('source_address' in output
                        and output['source_address'] == address):
                    output['txid'] = transaction['hash']
                    outputs.append(output)
            except BOCError:
                # Ignore transactions without a BOC post
                pass
        return outputs
    print("Chain %s not supported yet in search_address()" % chain)
    sys.exit(1)


def search_address_getcid(address, filehash, chain, key):
    """Search for all transactions by the provided address and looks for
    BoCA posts that have the hash and IPFS address. It will then
    download the file/folder from IPFS and create an array for
    everything that matches

    :param address: Address to query
    :type address: ``str``
    :param filehash: Filehash to check matches against BoCA posts
    :type filehash: ``str``
    :param chain: Blockchain to query
    :type chain: ``str``
    :param key: Private key to be used for decryption
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet``
    :rtype: ``int``
    """

    print("Searching for transactions involving: %s" % address)
    if chain in ('BCH', 'tBCH'):
        transactions = get_transactions_local(address, chain)
    else:
        print("Chain %s not supported yet in search_address_getcid()" % chain)
        sys.exit(1)
    for transaction in transactions:
        try:
            match = get_boc_hash(transaction, filehash, chain, True)
            ipfs_download = Path(match['ipfs_hash'])
            try:
                address_id = match['source_address'].split(':')[1]
                boca.ipfs.download_from_ipfs(ipfs_download, Path(address_id))
                file_to_decrypt = Path(address_id, ipfs_download)

                if (file_to_decrypt.is_dir() and key is not False):
                    print(("IPFS address was a folder: %s. Cannot decrypt a " +
                           "folder.") % file_to_decrypt)
                    sys.exit(1)
                elif (file_to_decrypt.is_dir() and key is False):
                    file_to_verify = Path(file_to_decrypt, 'index.txt')
                    if file_to_verify.is_file():
                        try:
                            boca.ipfs.check_index(file_to_verify)
                        except boca.ipfs.HashError:
                            print(("Hash failure against index file %s. " +
                                   "Exiting program.") % file_to_verify)
                            sys.exit(1)
                    else:
                        print(("Folder does not contain an index file and so" +
                               " cannot be verified: %s") % file_to_verify)
                        sys.exit(1)
                elif key is False:
                    file_to_verify = file_to_decrypt
                elif key is not False:
                    try:
                        decrypted_file = boca.crypto.dec_file(key,
                                                              file_to_decrypt)
                    except boca.crypto.DecryptionError as error:
                        print(error.args[0])
                        sys.exit(1)
                    except ValueError as error:
                        print(error.args[0])
                        sys.exit(1)
                    try:
                        output = boca.ipfs.unzip_file(decrypted_file)
                        if output == 0:
                            file_to_verify = decrypted_file
                        else:
                            if len(output) == 1:
                                only_folder = Path(output.pop())
                                file_to_verify = Path(only_folder, 'index.txt')
                                if file_to_verify.is_file():
                                    try:
                                        boca.ipfs.check_index(file_to_verify)
                                    except boca.ipfs.HashError:
                                        print(("Hash failure against index " +
                                               "file %s. Exiting program.")
                                              % file_to_verify)
                                        sys.exit(1)
                            else:
                                file_to_verify = decrypted_file
                    except zipfile.BadZipFile:
                        file_to_verify = decrypted_file
                filehash = boca.ipfs.hash_file(file_to_verify)
                try:
                    match = get_boc_hash(transaction, filehash, chain, False)
                except BOCError:
                    print("Data downloaded from IPFS, but hash did not match.")
                    print("Hash from downloaded file: %s" % filehash)
                    print("Transaction: %s" % transaction)
                    sys.exit(1)
                if ('source_address' in match) and ('confirmations' in match):
                    print(("Hash of local file %s matches hash placed on %s " +
                           "blockchain on %s UTC by %s with %d " +
                           "confirmation(s)")
                          % (file_to_verify, chain, datetime.
                             utcfromtimestamp(match['time']).
                             strftime('%Y-%m-%d %H:%M:%S'),
                             match['source_address'], match['confirmations']))
                else:
                    print(("Hash of local file %s matches hash in unconfirm" +
                           "ed transaction on %s blockchain by %s")
                          % (file_to_verify, chain, match['source_address']))
            except IPFSTimeoutError:
                print("Unable to download %s from IPFS" % ipfs_download)
        except BOCError:
            # Ignore transactions without a post-ipfs BOC post
            pass
    return 0


def select_mutual(pairs_mutual):
    """If there were no mutual exchanges, exit. If one, return that
    public key. If multiple give the user the choice and return the
    appropriate key.

    :param pairs_mutual: A list of tuples from find_mutual()
    :type pairs_mutual: ``list``
    :returns: Return one tuple from the provided list
    :rtype: ``list``
    """

    if len(pairs_mutual) == 0:
        print("No mutual exchanges found. In order to encrypt, you need to " +
              "send and receive funds with another address.")
        sys.exit(1)
    elif len(pairs_mutual) == 1:
        pair = pairs_mutual[0]
        print(("Only a single address that has a mutual transfer found. " +
               "Using: %s") % pair[0])
        return pair
    else:
        print("Mutual exchanges occurred with the following addresses:")
        count = 1
        # I'm sorting them so that the list is consistent when the code
        # is run multiple times.
        sorted_pairs = sorted(pairs_mutual)
        for pair in sorted_pairs:
            print("%d) %s" % (count, pair[0]))
            count = count + 1
        user_choice = 0
        while (user_choice < 1 or user_choice > len(sorted_pairs)):
            user_choice = int(input("Please enter your choice of above [1-"
                                    + str(len(sorted_pairs))+"]: "))
        print("You have selected %s" % (sorted_pairs[user_choice-1][0]))
        return sorted_pairs[user_choice-1]


def send_memo(key, message, chain):
    """Use the correct function to post the message based on the chain

    :param key: The private key needed to post
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet`` or
    ``eth_account.signers.local.LocalAccount``
    :param message: The message to be posted to the blockchain
    :type message: ``str``
    :param chain: The blockchain to post to
    :param type: ``str``
    :returns: Dictionary with TXID (and more details if (t)ETH)
    :rtype: ``dict``
    """

    if chain in ("BCH", "tBCH"):
        return send_memo_bch(key, message, chain)
    if chain == "ETH":
        return send_memo_eth(key, message)
    if chain == "tETH":
        return send_memo_testnet_eth(key, message)
    print("Chain not yet supported: %s" % chain)
    sys.exit(1)


def send_memo_bch(key, message, chain):
    """Posts the provided message to the BCH blockchain using the
    memo.cash protocol

    :param key: The key needed to post to the blockchain
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet``
    :param message: The message to be posted to the blockchain
    :type message: ``str``
    :param chain: The blockchain to post to (BCH/tBCH)
    :param type: ``str``
    :raises ValueError: If invalid chain is specified
    :raises ConnectionError: If unable to transmit the transaction
    :returns: Dictionary with TXID
    :rtype: ``dict``
    """

    post_memo_prefix = "026d02"
    pushdata_code = bytes_to_hex(get_op_pushdata_code(message))
    encoded_message = hex_to_bytes(post_memo_prefix + pushdata_code +
                                   bytes_to_hex(message.encode('utf-8')))
    if len(encoded_message) <= BCH_OP_RETURN_LIMIT:
        if chain == "tBCH":
            key.unspents = get_unspent_local(key.address, chain)
        elif chain == "BCH":
            key.get_unspents()
        else:
            raise ValueError("Chain not yet supported: %s" % chain)
        memo_tx = key.create_transaction([], message=encoded_message,
                                         leftover=key.address,
                                         custom_pushdata=True)
        try:
            response = broadcast_tx_local(memo_tx, chain)
            # broadcast_tx_local(memo_tx, chain)
            if not response:
                raise ConnectionError("Unable to broadcast transaction")
        except ConnectionError as exc:
            print("Error Exception in send_memo_bch()!", exc)
            sys.exit(1)
        return {'txid': calc_txid(memo_tx)}
    print("Error: message longer than %d bytes." % BCH_OP_RETURN_LIMIT)
    sys.exit(1)


def send_memo_eth(key, message):
    """Posts the provided message to the ETH blockchain using the data
    field in the transaction

    :param key: The key needed to post to the blockchain
    :type key: ``eth_account.signers.local.LocalAccount``
    :param message: The message to be posted to the blockchain
    :type message: ``str``
    :raises ConnectionError: If unable to transmit the transaction
    :returns: Dictionary with tx status, ID, and receipt
    :rtype: ``dict``
    """

    from boca.config import INFURA_URL_MAINNET
    print("Trying to make ETH transfer")
    w3main = Web3(Web3.HTTPProvider(INFURA_URL_MAINNET))

    historic_fees = w3main.eth.fee_history(1, 'latest')
    base_fee_per_gas = historic_fees['baseFeePerGas'][0]
    txn_dict = {
            'to': key.address,
            'value': 0,
            'maxPriorityFeePerGas': MAX_PRIORITY_FEE_PER_GAS_MAIN,
            'maxFeePerGas': base_fee_per_gas + MAX_PRIORITY_FEE_PER_GAS_MAIN,
            'nonce': w3main.eth.getTransactionCount(key.address),
            'chainId': 1,
            'data': message.encode('utf-8')
    }
    txn_dict['gas'] = w3main.eth.estimate_gas(txn_dict)
    signed_txn = w3main.eth.account.sign_transaction(txn_dict, key.key)
    try:
        txn_hash = w3main.eth.send_raw_transaction(signed_txn.rawTransaction)
    except ValueError as exc:
        print("Transaction failed!")
        balance_test_w = w3main.eth.getBalance(key.address)
        balance_test = w3main.fromWei(balance_test_w, 'gwei')
        print(f"ETH Balance:          {balance_test:.9f} Gwei")
        fee_w = txn_dict['gas'] * txn_dict['maxFeePerGas']
        total_cost_w = txn_dict['value'] + fee_w
        total_cost = w3main.fromWei(total_cost_w, 'gwei')
        print(f"Required balance:     {total_cost:.9f} Gwei")
        print(f"Try reduce amount by: {total_cost - balance_test:.9f} Gwei")
        print("Or increase funds in wallet.")
        return({'status': 'failed', 'error': exc,
                'txn_dict': txn_dict})

    txn_receipt = None
    count = 0
    pause = 10
    while txn_receipt is None and (count < 30):
        try:
            txn_receipt = w3main.eth.getTransactionReceipt(txn_hash)
        except TransactionNotFound:
            print(("Waiting for the transaction to be confirmed. ... " +
                   "sleeping for %d sec") % pause)
            sleep(pause)
    if txn_receipt is None:
        return({'status': 'failed', 'error': 'timeout'})
    return({'status': 'added', 'txn_receipt': txn_receipt,
            'txid': HexBytes(txn_receipt['transactionHash']).hex()})


def send_memo_testnet_eth(key, message):
    """Posts the provided message to the (testnet) ETH blockchain using
    the data field in the transaction

    :param key: The key needed to post to the blockchain
    :type key: ``eth_account.signers.local.LocalAccount``
    :param message: The message to be posted to the blockchain
    :type message: ``str``
    :raises ConnectionError: If unable to transmit the transaction
    :returns: Dictionary with tx status, ID, and receipt
    :rtype: ``dict``
    """

    from boca.config import INFURA_URL_TESTNET
    print("Trying to make testnet ETH transfer")
    w3test = Web3(Web3.HTTPProvider(INFURA_URL_TESTNET))
    historic_fees = w3test.eth.fee_history(1, 'latest')
    base_fee_per_gas = historic_fees['baseFeePerGas'][0]
    txn_dict = {
            'to': key.address,
            'value': 0,
            'maxPriorityFeePerGas': MAX_PRIORITY_FEE_PER_GAS_TEST,
            'maxFeePerGas': base_fee_per_gas + MAX_PRIORITY_FEE_PER_GAS_TEST,
            'nonce': w3test.eth.getTransactionCount(key.address),
            'chainId': 3,
            'data': message.encode('utf-8'),
    }
    txn_dict['gas'] = w3test.eth.estimate_gas(txn_dict)
    signed_txn = w3test.eth.account.sign_transaction(txn_dict, key.key)
    try:
        txn_hash = w3test.eth.send_raw_transaction(signed_txn.rawTransaction)
    except ValueError as exc:
        print("Transaction failed!")
        balance_test_w = w3test.eth.getBalance(key.address)
        balance_test = w3test.fromWei(balance_test_w, 'gwei')
        print(f"(testnet) ETH Balance: {balance_test:.9f} Gwei")
        fee_w = txn_dict['gas'] * txn_dict['maxFeePerGas']
        total_cost_w = txn_dict['value'] + fee_w
        total_cost = w3test.fromWei(total_cost_w, 'gwei')
        print(f"Required balance:      {total_cost:.9f} Gwei")
        print(f"Try reduce amount by:  {total_cost - balance_test:.9f} Gwei")
        print("Or increase funds in wallet.")
        return({'status': 'failed', 'error': exc,
                'txn_dict': txn_dict})

    txn_receipt = None
    count = 0
    pause = 10
    while txn_receipt is None and (count < 30):
        try:
            txn_receipt = w3test.eth.getTransactionReceipt(txn_hash)
        except TransactionNotFound:
            print(("Waiting for the transaction to be confirmed. ... " +
                   "sleeping for %d sec") % pause)
            sleep(pause)
            pause = 2*pause
    if txn_receipt is None:
        return({'status': 'failed', 'error': 'timeout'})
    return({'status': 'added', 'txn_receipt': txn_receipt,
            'txid': HexBytes(txn_receipt['transactionHash']).hex()})


def spend_eth(key, address, amount):
    """Send an amount of ETH to the specified address

    :param key: The key used to send the ETH
    :type key: ``eth_account.signers.local.LocalAccount``
    :param address: The destination address to send the ETH to
    :type address: ``str``
    :param amount: The amount of ETH to send
    :type amount: ``float``
    :returns: Transaction details
    :rtype: ``dict``
    """
    from boca.config import INFURA_URL_MAINNET
    print("Trying to make ETH transfer")
    w3main = Web3(Web3.HTTPProvider(INFURA_URL_MAINNET))

    historic_fees = w3main.eth.fee_history(1, 'latest')
    base_fee_per_gas = historic_fees['baseFeePerGas'][0]
    txn_dict = {
            'to': address,
            'value': w3main.toWei(amount, 'ether'),
            'maxPriorityFeePerGas': MAX_PRIORITY_FEE_PER_GAS_MAIN,
            'maxFeePerGas': base_fee_per_gas + MAX_PRIORITY_FEE_PER_GAS_MAIN,
            'nonce': w3main.eth.getTransactionCount(key.address),
            'chainId': 1,
    }
    txn_dict['gas'] = w3main.eth.estimate_gas(txn_dict)
    signed_txn = w3main.eth.account.sign_transaction(txn_dict, key.key)
    try:
        txn_hash = w3main.eth.send_raw_transaction(signed_txn.rawTransaction)
    except ValueError as exc:
        print("Transaction failed!")
        balance_test_w = w3main.eth.getBalance(key.address)
        balance_test = w3main.fromWei(balance_test_w, 'gwei')
        print(f"ETH Balance:          {balance_test:.9f} Gwei")
        fee_w = txn_dict['gas'] * txn_dict['maxFeePerGas']
        total_cost_w = txn_dict['value'] + fee_w
        total_cost = w3main.fromWei(total_cost_w, 'gwei')
        print(f"Required balance:     {total_cost:.9f} Gwei")
        print(f"Try reduce amount by: {total_cost - balance_test:.9f} Gwei")
        print("Or increase funds in wallet.")
        return({'status': 'failed', 'error': exc,
                'txn_dict': txn_dict})

    txn_receipt = None
    count = 0
    pause = 10
    while txn_receipt is None and (count < 30):
        try:
            txn_receipt = w3main.eth.getTransactionReceipt(txn_hash)
        except TransactionNotFound:
            print(("Waiting for the transaction to be confirmed. ... " +
                   "sleeping for %d sec") % pause)
            sleep(pause)
            pause = 2*pause
    if txn_receipt is None:
        return({'status': 'failed', 'error': 'timeout'})
    return({'status': 'added', 'txn_receipt': txn_receipt,
            'txid': HexBytes(txn_receipt['transactionHash']).hex()})


def spend_testnet_eth(key, address, amount):
    """Send an amount of (testnet) ETH to the specified address

    :param key: The key used to send the ETH
    :type key: ``eth_account.signers.local.LocalAccount``
    :param address: The destination address to send the ETH to
    :type address: ``str``
    :param amount: The amount of ETH to send
    :type amount: ``float``
    :returns: Transaction details
    :rtype: ``dict``
    """
    from boca.config import INFURA_URL_TESTNET
    print("Trying to make testnet ETH transfer")
    w3test = Web3(Web3.HTTPProvider(INFURA_URL_TESTNET))
    historic_fees = w3test.eth.fee_history(1, 'latest')
    base_fee_per_gas = historic_fees['baseFeePerGas'][0]
    txn_dict = {
            'to': address,
            'value': w3test.toWei(amount, 'ether'),
            'maxPriorityFeePerGas': MAX_PRIORITY_FEE_PER_GAS_TEST,
            'maxFeePerGas': base_fee_per_gas + MAX_PRIORITY_FEE_PER_GAS_TEST,
            'nonce': w3test.eth.getTransactionCount(key.address),
            'chainId': 3,
    }
    txn_dict['gas'] = w3test.eth.estimate_gas(txn_dict)
    signed_txn = w3test.eth.account.sign_transaction(txn_dict, key.key)
    try:
        txn_hash = w3test.eth.send_raw_transaction(signed_txn.rawTransaction)
    except ValueError as exc:
        print("Transaction failed!")
        balance_test_w = w3test.eth.getBalance(key.address)
        balance_test = w3test.fromWei(balance_test_w, 'gwei')
        print(f"(testnet) ETH Balance: {balance_test:.9f} Gwei")
        fee_w = txn_dict['gas'] * txn_dict['maxFeePerGas']
        total_cost_w = txn_dict['value'] + fee_w
        total_cost = w3test.fromWei(total_cost_w, 'gwei')
        print(f"Required balance:      {total_cost:.9f} Gwei")
        print(f"Try reduce amount by: {total_cost - balance_test:.9f} Gwei")
        print("Or increase funds in wallet.")
        return({'status': 'failed', 'error': exc,
                'txn_dict': txn_dict})
    txn_receipt = None
    count = 0
    pause = 10
    while txn_receipt is None and (count < 30):
        try:
            txn_receipt = w3test.eth.getTransactionReceipt(txn_hash)
        except TransactionNotFound:
            print(("Waiting for the transaction to be confirmed. ... " +
                   "sleeping for %d sec") % pause)
            sleep(pause)
            pause = 2*pause
    if txn_receipt is None:
        return({'status': 'failed', 'error': 'timeout'})
    return({'status': 'added', 'txn_receipt': txn_receipt,
            'txid': HexBytes(txn_receipt['transactionHash']).hex()})

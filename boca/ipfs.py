"""This contains all the IPFS related functions for BoCA
"""

import re
import sys
import zipfile

from hashlib import sha256
from pathlib import Path

from ipfshttpclient import connect
from ipfshttpclient.exceptions import ConnectionError as IPFSConnectionError

IPFS_GATEWAY = '/ip4/127.0.0.1/tcp/5001/http'
DEFAULT_TIMEOUT = 30


class HashError(Exception):
    """Raised whenever a file does not hash to an expected value
    """


def check_index(index_file):
    """Reads in the hashes from the provided file and checks if the
    file hashes match. The file hashes only start after the line:
    "Files:"

    :param index_file: The file with hashes to process
    :type index_file: ``pathlib.Path``
    :rtype: ``int``
    """

    index_path = Path(index_file).parents[0]
    with open(index_file, 'r') as file_index:
        start_of_files = False
        index_files = set()
        index_count = 0
        file_count = 0

        for line in file_index:
            line = line.strip()
            if line == "":
                pass
            elif line == "Files:":
                start_of_files = True
            elif start_of_files:
                (index_hash, path) = line.split(' ', 1)
                path_parts = path.split('/', 1)
                new_path = Path(index_path, path_parts[1])
                index_files.add(new_path)

                if index_hash != hash_file(new_path):
                    print("Hash in index file does not match file hash!")
                    print("File name: %s" % new_path)
                    print("Index file hash: %s" % index_hash)
                    print("File hash:       %s" % hash_file(new_path))
                    raise HashError("Hash mismatch in check_index()")
                index_count = index_count + 1
        print("Index file checked and all %d file hashes match." % index_count)

    file_count = 0
    for folder_content in index_path.rglob("*"):
        if folder_content.is_file():
            file_count = file_count + 1
    # The index.txt file is never included in the hashes, hence the +1
    if file_count != index_count + 1:
        print(("The following %d file(s) do not have hashes in the index " +
               "file, and so their authenticity cannot be assured!")
              % (file_count - (index_count + 1)))
        for folder_content in index_path.rglob("*"):
            if folder_content.is_file():
                if (folder_content not in index_files
                        and folder_content != Path(index_path, 'index.txt')):
                    print(folder_content)
    return 0


def download_from_ipfs(cid, target=Path.cwd()):
    """Download a file from IPFS

    :param cid: The IPFS CID for the desired content.
    :type cid: ``str``
    :param target: The local folder to save the content.
    :type target: ``pathlib.Path``
    :rtype: ``int``
    """

    download_location = Path(target, cid)
    try:
        client = connect(IPFS_GATEWAY)
    except IPFSConnectionError:
        print("Cannot reach gateway. Please make sure local IPFS daemon is " +
              "running:")
        sys.exit(1)
    client.get(cid, target, timeout=DEFAULT_TIMEOUT)
    if download_location.is_dir():
        print("Downloaded folder from IPFS: %s" % cid)
    elif download_location.is_file():
        print("Downloaded file from IPFS: %s" % cid)
    else:
        print("Unable to process content: %s" % cid)
        sys.exit(1)
    return 0


def hash_file(filename):
    """Hash a file using SHA-256

    :param filename: The file to be hashed.
    :type filename: ``pathlib.Path``
    :returns: The hash of the file in hex.
    :rtype: ``str``
    """
    sha256_hash = sha256()
    try:
        with open(filename, "rb") as file_in:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: file_in.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except IOError:
        print("Unable to open file %s" % filename)
        sys.exit(1)


def parse_image_file(filename):
    """Scans through a file looking for any hex strings that could be
    hashes.

    :param filename: The name of the file to scan.
    :type filename: ``pathlib.Path``
    :returns: A list or unique hashes found, sorted by content.
    :rtype: ``list``
    """

    # The lengths of common hash digests in hex digits
    # (if you multiply by 4 you get the bit length)
    hash_lengths = [32, 40, 48, 56, 64, 90, 96, 128]
    print("Trying to parse image file")
    patterns = []
    found_hashes = []
    for h_l in hash_lengths:
        # The following regular expressions represent (in order):
        # the hash is the whole line
        # the hash is at the start of the line
        # the hash is at the end of the line
        # the hash is in the middle of the line
        patterns.append([re.compile(r'^[0-9a-f]{'+str(h_l)+','+str(h_l)+'}$'),
            re.compile(r'^[0-9a-f]{'+str(h_l)+','+str(h_l)+'}[^0-9a-f]'),
            re.compile(r'[^0-9a-f][0-9a-f]{'+str(h_l)+','+str(h_l)+'}$'),
            re.compile(r'[^0-9a-f][0-9a-f]{'+str(h_l)+','+str(h_l)+'}[^0-9a-f]')])
    try:
        with open(filename, "r") as file_in:
            lines = file_in.readlines()
            for line in lines:
                line = line.rstrip()
                for pattern in patterns:
                    all_matches = pattern[0].findall(line)
                    for match in all_matches:
                        found_hashes.append(match)
                    all_matches = pattern[1].findall(line)
                    for match in all_matches:
                        found_hashes.append(match[:-1])
                    all_matches = pattern[2].findall(line)
                    for match in all_matches:
                        found_hashes.append(match[1:])
                    all_matches = pattern[3].findall(line)
                    for match in all_matches:
                        found_hashes.append(match[1:-1])
    except IOError:
        print("Unable to open file %s" % filename)
        sys.exit(1)
    # Remove all duplicates
    found_hashes = list(dict.fromkeys(found_hashes))
    # Sort the hashes found
    found_hashes.sort()
    return found_hashes


def unzip_file(filename):
    """Unzip a file and extract all the contents.

    :param filename: The file to unzip.
    :type filename: ``pathlib.Path``
    :raises BadZipFile: If the file is not a valid zipfile.
    :returns: A set of all the lowest level folders of what was
    extracted.
    :rtype: ``set``
    """
    delete_files = False
    if filename.is_dir():
        raise zipfile.BadZipFile("Cannot unzip a folder.")
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        lowest_folders = set()
        all_zipped_files = zip_ref.namelist()
        for zipped_file in all_zipped_files:
            full_zipped_file = Path(filename.parent, zipped_file)
            if full_zipped_file.is_file():
                if delete_files:
                    full_zipped_file.unlink()
                else:
                    print(("Cannot extract contents of zip file (%s) as " +
                           "file (%s) already exist locally")
                          % (filename, zipped_file))
                    response = input("Do you wish to delete all existing " +
                                     "files? (y/n): ")
                    if response in ('Y', 'y'):
                        delete_files = True
                        print("Deleting file.")
                        full_zipped_file.unlink()
                    else:
                        raise FileExistsError
            lowest_folders.add(Path(zipped_file).parts[0])
        zip_ref.extractall(filename.parent)
        # print("File %s unzipped to these folder(s):" % filename)
        # print(lowest_folders)
        return lowest_folders


def upload_to_ipfs(filename):
    """Upload a file to IPFS network

    :param filename: The file to upload.
    :type filename: ``pathlib.Path``
    :returns: Dictionary containing IPFS CID and other details.
    :rtype: ``dict``
    """
    try:
        client = connect(IPFS_GATEWAY)
    except IPFSConnectionError:
        print("Cannot reach gateway. Please make sure local IPFS daemon is " +
              "running:")
        # print(e.args[0])
        sys.exit(1)
    res = client.add(filename, recursive=True, timeout=DEFAULT_TIMEOUT)
    return res


def zipdir(path, ziph):
    """Zip the contents of a folder

    :param path: Path of folder to be zipped.
    :type path: ``pathlib.Path``
    :param ziph: The zipfile handle.
    :type zipf: ``zipfile.ZipFile``
    """

    zpath = Path(path)
    for folder_content in zpath.rglob("*"):
        ziph.write(folder_content)

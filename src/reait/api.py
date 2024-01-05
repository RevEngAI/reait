#!/usr/bin/env python
from __future__ import print_function
from hashlib import sha256
from rich import print_json, print as rich_print
from sklearn.metrics.pairwise import cosine_similarity
import os
import re
import argparse
import requests
from numpy import array, vstack, mean, average, dot, arccos, pi
from pandas import DataFrame
import json
import tomli
from os.path import isfile
from sys import exit
from IPython import embed
import lief

__version__ = "0.0.19"

re_conf = {
    'apikey': 'l1br3',
    'host': 'https://api.reveng.ai',
    'model': 'binnet-0.2-x86',
    'verbose': False
}


def reveng_req(r: requests.request, end_point: str, data=None, ex_headers: dict = None, params=None, json_data: dict = None):
    url = f"{re_conf['host']}/{end_point}"
    headers = {"Authorization": f"{re_conf['apikey']}"}
    if ex_headers:
        headers.update(ex_headers)

    if re_conf['verbose']:
        print(f"""Making request {url}: 
        - headers: {headers}
        - data: {data}
        - json_data: {json_data}
        - params: {params}
        """)

    return r(url, headers=headers, json=json_data, data=data, params=params)


# Bin_id is referred to as hash in this program - to maintain usage BID = id of a binary bin_id = hash
# Assumes a file has been passed, correct hash only
# Returns the BID of the binary_id (hash)
def re_bid_search(bin_id: str):
    res = reveng_req(requests.get, f"/search?search=sha_256_hash:{bin_id}&state=All")

    bid = -1

    # Valid request
    if res.status_code == 200:

        # Check only one record is returned
        binaries_data = res.json()['binaries']
        if len(binaries_data) > 1:

            print(f"[+] {len(binaries_data)} matches found for hash: {bin_id}.")
            if len(binaries_data) > 1:

                options_dict = {}
                count = 0

                for binary in binaries_data:
                    print(
                        f"[+] {count} - ID: {binary['binary_id']}, Name: {binary['binary_name']}, "
                        f"Creation: {binary['creation']}, Model: {binary['model_name']}, Owner: {binary['owner']}, Status: {binary['status']}")
                    options_dict[count] = binary['binary_id']
                    count += 1

                user_input = input("[+] Please enter the option you want to use for this operation:")

                try:

                    option_number = int(user_input)

                    bid = options_dict.get(option_number, -1)

                    if bid == -1:
                        print("[!] Invalid option.")

                except Exception as e:
                    bid = -1
                    print("[!] Invalid option.")

            # Only 1 match found
            elif len(binaries_data) == 1:
                binary = binaries_data[0]
                bid = binary['binary_id']

            else:
                print(f"[!] No matches found for hash: {bin_id}.")
                return bid
        elif len(binaries_data) == 1:
            print(f"[+] Only one record exists, selecting - ID: {binaries_data[0]['binary_id']}, Name: {binaries_data[0]['binary_name']}, Creation: {binaries_data[0]['creation']}, Model: {binaries_data[0]['model_name']}, Owner: {binaries_data[0]['owner']}, Status: {binaries_data[0]['status']}")
            binary = binaries_data[0]
            bid = binary['binary_id']
        else:
            print(f"[!] No matches found for hash: {bin_id}.")
            return bid

    elif res.status_code == 400:
        print(f"[!] Bad Request.")

    else:
        print(f"[!] Internal Server Error.")

    return bid


def RE_delete(fpath: str):
    """
        Delete analysis results for Binary ID in command
    """
    bin_id = binary_id(fpath)
    bid = re_bid_search(bin_id)

    res = reveng_req(requests.delete, f"/analyse/{bid}")
    if res.status_code == 200:
        print(f"[+] Success. Securely deleted {bin_id} analysis")
    elif res.status_code == 404:
        print(f"[!] Error, analysis not found for {bin_id}.")
    else:
        print(f"[!] Error deleting binary {bin_id} under. Server returned {res.status_code}.")
    return


def RE_analyse(fpath: str, model_name: str = None, isa_options: str = None, platform_options: str = None,
               file_options: str = None, dynamic_execution: bool = False, command_line_args: str = None,
               scope: str = None, tags: list = None, priority: int = 0):
    """
        Start analysis job for binary file
    """
    filename = os.path.basename(fpath)
    bin_id = binary_id(fpath)
    params = {'file_name': filename, "sha_256_hash": bin_id}

    for p_name in (
            'model_name', 'isa_options', 'platform_options', 'file_options', 'dynamic_execution', 'command_line_args',
            'scope',
            'tags', 'priority'):
        p_value = locals()[p_name]
        if p_value:
            params[p_name] = p_value

    res = reveng_req(requests.post, f"analyse", json_data=params)
    if res.status_code == 200:
        #print(res)
        print("[+] Successfully submitted binary for analysis.")
        print(f"[+] {fpath} - {binary_id(fpath)}")
        return res

    if res.status_code == 400:
        print(res.text)
        response = res.json()

        if 'error' in response.keys():
            print(
                f"[-] Error analysing {fpath} - {response['error']}.")
            return res

    res.raise_for_status()


def RE_upload(fpath: str):
    """
        Upload binary to Server
    """
    res = reveng_req(requests.post, f"upload", data=open(fpath, 'rb').read())
    if res.status_code == 200:
        print("[+] Successfully uploaded binary to your account.")
        print(f"[+] {fpath} - {binary_id(fpath)}")
        return res

    if res.status_code == 400:
        response = res.json()
        if 'already exists' in response['reason']:
            print(f"[-] {fpath} already exists. Please check the results log file for {binary_id(fpath)}")
            return True

        if 'non-empty' in response['reason']:
            print(f"[-] Please pass a non-empty file")
            return True

    res.raise_for_status()


def RE_embeddings(fpath: str):
    """
        Fetch symbol embeddings
    """
    bin_id = binary_id(fpath)
    bid = re_bid_search(bin_id)

    res = reveng_req(requests.get, f"embeddings/{bid}")
    if res.status_code == 400:
        print(f"[-] Analysis for {bin_id} still in progress. Please check the logs (-l) and try again later.")

    res.raise_for_status()
    return res.json()


def RE_signature(fpath: str):
    """
        Fetch binary BinNet signature
    """
    bin_id = binary_id(fpath)
    bid = re_bid_search(bin_id)

    res = reveng_req(requests.get, f"signature/{bid}")
    if res.status_code == 425:
        print(f"[-] Analysis for {bin_id} still in progress. Please check the logs (-l) and try again later.")

    res.raise_for_status()
    return res.json()


def RE_embedding(fpath: str, start_vaddr: int, end_vaddr: int = None, base_vaddr: int = None, model: str = None):
    """
        Fetch embedding for custom symbol range
    """
    params = {}

    if end_vaddr:
        params['end_vaddr']: end_vaddr
    if base_vaddr:
        params['base_vaddr']: base_vaddr
    if model:
        params['model']: model

    res = reveng_req(requests.get, f"embedding/{binary_id(fpath)}/{start_vaddr}", params=params)
    if res.status_code == 425:
        print(f"[-] Analysis for {binary_id(fpath)} still in progress. Please check the logs (-l) and try again later.")
        return

    res.raise_for_status()
    return res.json()


def RE_logs(fpath: str):
    """
        Delete analysis results for Binary ID in command
    """
    bin_id = binary_id(fpath)
    bid = re_bid_search(bin_id)

    if bid == -1:
        return

    res = reveng_req(requests.get, f"/logs/{bid}")
    if res.status_code == 200:
        print(res.text)
        return
    elif res.status_code == 404:
        print(f"[!] Error, binary analysis for {bin_id} not found.")
        return

    res.raise_for_status()


def RE_cves(fpath: str):
    """
        Check for known CVEs in Binary 
    """
    bin_id = binary_id(fpath)
    bid = re_bid_search(bin_id)

    if bid == -1:
        return

    res = reveng_req(requests.get, f"/cves/{bid}")
    if res.status_code == 200:
        cves = json.loads(res.text)
        rich_print(
            f"[bold blue]Checking for known CVEs embedded inside [/bold blue] [bold bright_green]{fpath}[/bold bright_green]:")
        if len(cves) == 0:
            rich_print(f"[bold bright_green]0 CVEs found.[/bold bright_green]")
        else:
            rich_print(f"[bold red]Warning CVEs found![/bold red]")
            print_json(data=cves)
        return
    elif res.status_code == 404:
        print(f"[!] Error, binary analysis for {bin_id} not found.")
        return

    res.raise_for_status()


def RE_status(fpath: str):
    """
        Check for known CVEs in Binary 
    """
    bin_id = binary_id(fpath)
    bid = re_bid_search(bin_id)

    if bid == -1:
        return

    res = reveng_req(requests.get, f"/analyse/status/{bid}")
    if res.status_code == 200:
        return res.json()
    elif res.status_code == 400:
        print(f"[!] Error, status not found for {bin_id} not found.")
        return res.json()

    res.raise_for_status()


def RE_compute_distance(embedding: list, embeddings: list, nns: int = 5):
    """
        Compute the cosine distance between source embedding and embeddinsg from binary
    """
    df = DataFrame(data=embeddings)
    np_embedding = array(embedding).reshape(1, -1)
    source_embeddings = vstack(df['embedding'].values)
    closest = cosine_similarity(source_embeddings, np_embedding).squeeze().argsort()[::-1][:nns]
    distances = cosine_similarity(source_embeddings[closest], np_embedding)
    # match closest embeddings with similarity
    closest_df = df.iloc[closest]
    # create json similarity object
    similarities = list(zip(distances, closest_df.index.tolist()))
    json_sims = [{'similaritiy': float(d[0]), 'vaddr': int(df.iloc[v]['vaddr']), 'name': str(df.iloc[v]['name']),
                  'size': int(df.iloc[v]['size'])} for d, v in similarities]
    return json_sims


def RE_nearest_symbols(embedding: list, model_name, nns: int = 5, collections: list = None, ignore_hashes: list = None):
    """
        Get function name suggestions for an embedding
        :param embedding: embedding vector as python list
        :param nns: Number of nearest neighbors
        :param collections: list of collections to search through
        :param ignore_hashes: list[str] SHA 256 hash of binary file to ignore symbols from (usually the current binary)
    """
    params = {'nns': nns, 'model_name': model_name}

    if collections:
        # api param is collection, not collections
        params['collection'] = "|".join(collections)

    if ignore_hashes:
        params['ignore_hashes'] = ignore_hashes

    res = reveng_req(requests.post, "ann/symbol", data=json.dumps(embedding), params=params)
    res.raise_for_status()
    f_suggestions = res.json()
    return f_suggestions


def RE_nearest_binaries(embedding: list, model_name, nns: int = 5, collections: list = None,
                        ignore_hashes: list = None):
    """
        Get executable suggestions for a binary embedding
        :param embedding: embedding vector as python list
        :param nns: Number of nearest neighbors
        :param collections: list of collections RevEng.AI collection names to search through
        :param ignore_hashes: list[str] SHA 256 hash of binary files to ignore symbols from (usually the current binary)
    """
    params = {'nns': nns, 'model_name': model_name}

    if collections:
        # api param is collection, not collections
        params['collection'] = "|".join(collections)

    if ignore_hashes:
        params['ignore_hashes'] = ignore_hashes

    res = reveng_req(requests.post, "ann/binary", data=json.dumps(embedding), params=params)
    res.raise_for_status()
    b_suggestions = res.json()
    return b_suggestions


def RE_SBOM(fpath: str):
    """
        Get Software Bill Of Materials for binary
        :param fpath: File path for binaty to analyse
        :param model_name: str model name of RevEng.AI AI model
    """
    bid = re_bid_search(binary_id(fpath))

    if bid == -1:
        return

    res = reveng_req(requests.get, f"sboms/{bid}")
    res.raise_for_status()
    sbom = res.json()
    print_json(data=sbom)


def binary_id(path: str):
    """Take the SHA-256 hash of binary file"""
    hf = sha256()
    with open(path, "rb") as f:
        c = f.read()
        hf.update(c)
    return hf.hexdigest()


def _binary_isa(lief_hdlr, exec_type):
    """
        Get executable file format
    """
    if exec_type == "elf":
        machine_type = lief_hdlr.header.machine_type
        if machine_type == lief.ELF.ARCH.i386:
            return "x86"
        elif machine_type == lief.ELF.ARCH.x86_64:
            return "x86_64"

    elif exec_type == "pe":
        machine_type = lief_hdlr.header.machine
        if machine_type == lief.PE.MACHINE_TYPES.I386:
            return "x86"
        elif machine_type == lief.PE.MACHINE_TYPES.AMD64:
            return "x86_64"

    elif exec_type == "macho":
        machine_type = lief_hdlr.header.cpu_type
        if machine_type == lief.MachO.CPU_TYPES.x86:
            return "x86"
        elif machine_type == lief.MachO.CPU_TYPES.x86_64:
            return "x86_64"

    raise RuntimeError(f"Error, failed to determine or unsupported ISA for exec_type:{exec_type}")


def _binary_format(lief_hdlr):
    """
        Get executable file format
    """
    if lief_hdlr.format == lief_hdlr.format.PE:
        return "pe"
    if lief_hdlr.format == lief_hdlr.format.ELF:
        return "elf"
    if lief_hdlr.format == lief_hdlr.format.MACHO:
        return "macho"

    raise RuntimeError("Error, could not determine binary format")


def file_type(fpath: str):
    """
        Determine ISA for binary
    """
    binary = lief.parse(fpath)

    # handle PE and ELF files
    file_format = _binary_format(binary)
    isa = _binary_isa(binary, file_format)
    return file_format, isa


def parse_config():
    """
        Parse ~/.reait.toml config file
    """
    if not os.path.exists(os.path.expanduser("~/.reait.toml")):
        return

    with open(os.path.expanduser("~/.reait.toml"), "r") as file:
        config = tomli.loads(file.read())
        for key in ('apikey', 'host', 'model'):
            if key in config:
                re_conf[key] = config[key]


def angular_distance(x, y):
    """
    Compute angular distance between two embedding vectors
    Normalised euclidean distance
    """
    cos = dot(x, y) / ((dot(x, x) * dot(y, y)) ** 0.5)
    return 1.0 - arccos(cos) / pi

#!/usr/bin/env python
from __future__ import print_function
from json import dumps
from os import system
from tqdm import tqdm 
from hashlib import sha256
from rich import print_json, print as rich_print
from sklearn.metrics.pairwise import cosine_similarity
import os
import re
import argparse
import requests
from numpy import array, vstack, mean
from pandas import DataFrame
import json
import tomli
from os.path import isfile
from sys import exit
from IPython import embed

__version__ = "0.0.15"

re_conf = {
    'apikey' : 'l1br3', 
    'host' : 'https://api.reveng.ai',
    'model': 'binnet-0.1'
}

def reveng_req(r: requests.request, end_point: str, data=None, ex_headers: dict = None, params=None):
    url = f"{re_conf['host']}/{end_point}"
    headers = { "Authorization": f"Bearer {re_conf['apikey']}" }
    if ex_headers:
        headers.update(ex_headers)
    return r(url, headers=headers, data=data, params=params)


def RE_delete(fpath: str):
    """
        Delete analysis results for Binary ID in command
    """
    bin_id = binary_id(fpath)
    res = reveng_req(requests.delete, f"{bin_id}")
    if res.status_code == 200:
        print(f"[+] Success. Securely deleted {fpath} analysis")
    elif res.status_code == 404:
        print("[!] Error, binary analysis not found.")
    else:
        print(f"[!] Error deleteing binary {bin_id}. Server returned {res.status_code}.")
    return


def RE_analyse(fpath: str, model: str = None):
    """
        Start analysis job for binary file
    """
    params={}
    if model:
        params['model'] = model
    res = reveng_req(requests.post, f"analyse", data=open(fpath, 'rb').read(), params=params)
    if res.status_code == 200:
        print("[+] Successfully submitted binary for analysis.")
        print(f"[+] {fpath} - {binary_id(fpath)}")
        return res

    if res.status_code == 400:
        if 'already exists' in json.loads(res.text)['reason']:
            print(f"[-] {fpath} already analysed. Please check the results log file for {binary_id(fpath)}")
            return True

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
        if 'already exists' in json.loads(res.text)['reason']:
            print(f"[-] {fpath} already exists. Please check the results log file for {binary_id(fpath)}")
            return True

    res.raise_for_status()


def RE_embeddings(fpath: str):
    """
        Fetch symbol embeddings
    """
    res = reveng_req(requests.get, f"embeddings/{binary_id(fpath)}")
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
    res = reveng_req(requests.get, f"/log/{bin_id}")
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
    res = reveng_req(requests.get, f"/cves/{bin_id}")
    if res.status_code == 200:
        cves = json.loads(res.text)
        rich_print(f"[bold blue]Checking for known CVEs embedded inside [/bold blue] [bold bright_green]{fpath}[/bold bright_green]:")
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


#def RE_compute_distance(embedding: list, fpath_source: str, nns: int = 5):
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
    json_sims = [{'similaritiy': float(d[0]), 'vaddr': int(df.iloc[v]['vaddr'])} for d, v in similarities]
    return json_sims


def RE_nearest_symbols(embedding: list, nns: int = 5, collections : list = None):
    """
        Get function name suggestions for an embedding
        :param embedding: embedding vector as python list
        :param nns: Number of nearest neighbors
        :param collections: str RegEx to search through RevEng.AI collections
    """
    params={'nns': nns}

    if collections:
        params['collections'] = collections

    res = reveng_req(requests.post, "ann", data=json.dumps(embedding), params=params)
    res.raise_for_status()
    f_suggestions = res.json()
    print_json(data=f_suggestions)

def binary_id(path: str):
    """Take the SHA-256 hash of binary file"""
    hf = sha256()
    with open(path, "rb") as f:
        c = f.read()
        hf.update(c)
    return hf.hexdigest()


def parse_config():
    """
        Parse ~/.reait.toml config file
    """     
    if not os.path.exists(os.path.expanduser("~/.reait.toml")):
        return

    with open(os.path.expanduser("~/.reait.toml"), "r") as file:
        config = tomli.loads(file.read())
        for key in ('apikey', 'host'):
            if key in config:
                re_conf[key] = config[key]

def version():
    """
        Display program version
    """
    rich_print(f"[bold red]reait[/bold red] [bold bright_green]v{__version__}[/bold bright_green]")
    print_json(data=re_conf)


def main() -> None:
    """
    Tool entry
    """
    parse_config()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-b", "--binary", default="", help="Path of binary to analyse")
    parser.add_argument("-a", "--analyse", action='store_true', help="Perform a full analysis and generate embeddings for every symbol")
    parser.add_argument("--no-embeddings", action='store_true', help="Only perform binary analysis. Do not generate embeddings for symbols")
    parser.add_argument("--base-address", help="Image base of the executable image to map for remote analysis")
    parser.add_argument("-A", action='store_true', help="Upload and Analyse a new binary")
    parser.add_argument("-u", "--upload", action='store_true', help="Upload a new binary to remote server")
    parser.add_argument("-n", "--ann", action='store_true', help="Fetch Approximate Nearest Neighbours (ANNs) for embedding")
    parser.add_argument("--embedding", help="Path of JSON file containing a BinNet embedding")
    parser.add_argument("--nns", default="5", help="Number of approximate nearest neighbors to fetch")
    parser.add_argument("--collections", default=None, help="Regex string to select RevEng.AI collections for filtering e.g., libc")
    parser.add_argument("--found-in", help="ANN flag to limit to embeddings returned to those found in specific binary")
    parser.add_argument("--from-file", help="ANN flag to limit to embeddings returned to those found in JSON embeddings file")
    parser.add_argument("-c", "--cves", action="store_true", help="Check for CVEs found inside binary")
    parser.add_argument("-C", "--sca", action="store_true", help="Perform Software Composition Anaysis to identify common libraries embedded in binary")
    parser.add_argument("-m", "--model", default="binnet-0.1", help="AI model used to generate embeddings")
    parser.add_argument("-x", "--extract", action='store_true', help="Fetch embeddings for binary")
    parser.add_argument("--start-address", help="Start vaddr of the function to extract embeddings")
    parser.add_argument("--end-address", help="End vaddr of the function to extract embeddings")
    parser.add_argument("-s", "--summary", action='store_true', help="Average symbol embeddings in binary")
    parser.add_argument("-S", "--signature", action='store_true', help="Generate a RevEng.AI binary signature")
    parser.add_argument("-l", "--logs", action='store_true', help="Fetch analysis log file for binary")
    parser.add_argument("-d", "--delete", action='store_true', help="Delete all metadata associated with binary")
    parser.add_argument("-k", "--apikey", help="RevEng.AI API key")
    parser.add_argument("-h", "--host", help="Analysis Host (https://api.reveng.ai)")
    parser.add_argument("-v", "--version", action="store_true", help="Display version information")
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help=argparse._('Show this help message and exit'))
    args = parser.parse_args()

    if args.apikey:
        re_conf['apikey'] = args.apikey
    if args.host:
        re_conf['host'] = args.host
    if args.model:
        re_conf['model'] = args.model

    # display version and exit
    if args.version:
        version()
        exit(0)

    if args.A or args.analyse or args.extract or args.logs or args.delete or args.summary or args.upload:
        # verify binary is a file
        if not os.path.isfile(args.binary):
            print("[!] Error, please supply a valid binary file using '-b'.")
            parser.print_help()
            exit(-1)

    if args.upload:
        # upload binary first, them carry out actions
        print(f"[!] RE:upload not implemented. Use analyse.")
        exit(-1)

    if args.A:
        RE_analyse(args.binary)

    if args.analyse:
        RE_analyse(args.binary)

    elif args.extract:
        embeddings = RE_embeddings(args.binary)
        print_json(data=embeddings)

    elif args.summary:
        # Arithetic mean of symbol embeddings
        embeddings = RE_embeddings(args.binary)
        b_embed = mean(vstack(list(map(lambda x: array(x['embedding']), embeddings))), axis=0)
        print_json(data=b_embed.tolist())

    elif args.ann:
        source = None
        # parse embedding json file
        if not isfile(args.embedding):
            print("[!] Error, please supply a valid embedding JSON file using '-e'")
            parser.print_help()
            exit(-1)

        embedding = json.loads(open(args.embedding, 'r').read())

        # check for valid regex
        if args.collections:
            try:
                re.compile(args.collections)
            except re.error as e:
                print(f"[!] Error, invalid regex for collections - {args.collections}")
                exit(-1)

        if args.found_in:
            if not os.path.isfile(args.found_in):
                print("[!] Error, --found-in flag requires a path to a binary to search from")
                exit(-1)
            print(f"[+] Searching for symbols similar to embedding in binary {args.found_in}")
            embeddings = RE_embeddings(args.found_in)
            res = RE_compute_distance(embedding, embeddings, int(args.nns))
            print_json(data=res)
        elif args.from_file:
            if not os.path.isfile(args.from_file):
                print("[!] Error, --from-file flag requires a path to a JSON embeddings file")
                exit(-1)
            print(f"[+] Searching for symbols similar to embedding in binary {args.from_file}")
            res = RE_compute_distance(embedding, json.load(open(args.from_file, "r")), int(args.nns))
            print_json(data=res)
        else:
            print(f"[+] Searching for similar symbols to embedding in {'all' if not args.collections else args.collections} collections.")
            RE_nearest_symbols(embedding, int(args.nns), collections=args.collections)

    elif args.logs:
        RE_logs(args.binary)

    elif args.delete:
        RE_delete(args.binary)

    elif args.cves:
        RE_cves(args.binary)
    elif args.signature:
        print(f"[!] Error, feature not available yet")
        exit(-1)

    else:
        print("[!] Error, please supply an action command")
        parser.print_help()


if __name__ == '__main__':
    main()

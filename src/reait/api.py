#!/usr/bin/env python
from __future__ import print_function
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


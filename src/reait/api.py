#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, annotations

from hashlib import sha256

from sklearn.metrics.pairwise import cosine_similarity
from os.path import basename, exists, expanduser
from requests import request, Response
import requests
from numpy import array, vstack, dot, arccos, pi
from pandas import DataFrame
import json
import tomli
import logging
from lief import parse, ELF, PE, MachO

__version__ = "0.0.20"

re_conf = {
    "apikey": "l1br3",
    "host": "https://api.reveng.ai",
    "model": "binnet-0.2-x86"
}

logger = logging.getLogger("REAIT")


def reveng_req(r: request, end_point: str, data=None, ex_headers: dict = None, params=None,
               json_data: dict = None, timeout: int = 30) -> Response:
    """
    Constructs and sends a Request
    :param r: Method for the new Request
    :param end_point: Endpoint to add to the base URL
    :param ex_headers: Extended HTTP headers to add
    :param data: Dictionary, list of tuples, bytes, or file-like object to send in the body
    :param params: Dictionary, list of tuples or bytes to send in the query string for the query string
    :param json_data: A JSON serializable Python object to send in the body
    :param timeout: Number of seconds to stop waiting for a Response
    """
    url = f"{re_conf['host']}/{end_point}"
    headers = {"Authorization": re_conf["apikey"]}

    if ex_headers:
        headers.update(ex_headers)

    logger.debug("Making request %s:\n  - headers: %s\n  - data: %s\n  - json_data: %s\n  - params: %s",
                 url, headers, data, json_data, params)

    response: Response = r(url, headers=headers, json=json_data, data=data, params=params, timeout=timeout)

    logger.debug("Making response %s:\n  - headers: %s\n  - status_code: %d\n  - content: %s",
                 url, response.headers, response.status_code, response.text)

    return response


def re_hash_check(bin_id: str) -> bool:
    status = False
    res = reveng_req(requests.get, f"search?search=sha_256_hash:{bin_id}&state=All&user_owned=true")

    if res.status_code == 200:
        binaries_data = res.json()["binaries"]
        status = len(binaries_data) > 0
    elif res.status_code == 400:
        logger.warning("Bad Request: %s", res.text)
    else:
        logger.error("Internal Server Error.")

    res.raise_for_status()
    return status


# Bin_id is referred to as hash in this program - to maintain usage BID = id of a binary bin_id = hash
# Assumes a file has been passed, correct hash only
# Returns the BID of the binary_id (hash)
def re_bid_search(bin_id: str) -> int:
    res = reveng_req(requests.get, f"search?search=sha_256_hash:{bin_id}&state=All")

    bid = -1

    # Valid request
    if res.status_code == 200:
        # Check only one record is returned
        binaries_data = res.json()["binaries"]

        if len(binaries_data) > 1:
            logger.info("%d matches found for hash: %s.", len(binaries_data), bin_id)

            if len(binaries_data) > 1:
                options_dict = {}

                for idx, binary in enumerate(binaries_data):
                    logger.info("[%d] - ID: {}, Name: %s, Creation: %s, Model: %s, Owner: %s, Status: %s",
                                idx, binary["binary_id"], binary["binary_name"], binary["creation"],
                                binary["model_name"], binary["owner"], binary["status"])

                    options_dict[idx] = binary["binary_id"]

                user_input = input("[+] Please enter the option you want to use for this operation:")

                try:
                    option_number = int(user_input)

                    bid = options_dict.get(option_number, -1)

                    if bid == -1:
                        logger.warning("Invalid option.")
                except Exception:
                    bid = -1
                    logger.warning("Invalid option.")
            # Only 1 match found
            elif len(binaries_data) == 1:
                binary = binaries_data[0]
                bid = binary["binary_id"]
            else:
                logger.warning("No matches found for hash: %s.", bin_id)
        elif len(binaries_data) == 1:
            binary = binaries_data[0]
            bid = binary["binary_id"]

            logger.info("Only one record exists, selecting - ID: %d, Name: %s, "
                        "Creation: %s, Model: %s, Owner: %s, Status: %s",
                        bid, binary["binary_name"], binary["creation"],
                        binary["model_name"], binary["owner"], binary["status"])
        else:
            logger.warning("No matches found for hash: %s.", bin_id)
    elif res.status_code == 400:
        logger.warning("Bad Request: %s", res.text)
        raise Exception(f"Bad Request: {res.text}")
    else:
        logger.error("Internal Server Error.")
        raise Exception(f"Internal Server Error")

    res.raise_for_status()
    return bid


def RE_delete(fpath: str, binary_id: int = 0) -> Response | None:
    """
    Delete analysis results for Binary ID in command
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.delete, f"analyse/{bid}")

    if res.status_code == 200:
        logger.info("Securely deleted %s analysis.", bin_id)
    elif res.status_code == 404:
        logger.warning("Error analysis not found for %s.", bin_id)
    else:
        logger.error("Error deleting binary %s under. Server returned %d.", bin_id, res.status_code)

    res.raise_for_status()
    return res


def RE_analyse(fpath: str, model_name: str = None, isa_options: str = None, platform_options: str = None,
               file_options: str = None, dynamic_execution: bool = False, command_line_args: str = None,
               scope: str = None, tags: list = None, priority: int = 0,
               duplicate: bool = False, symbols: dict = None) -> Response | None:
    """
    Start analysis job for binary file
    :param fpath: File path for binary to analyse
    :param model_name: Binary model name
    :param isa_options: Executable ISA
    :param file_options: File options
    :param platform_options: OS platform
    :param dynamic_execution: Enable dynamic execution in sandbox during analysis
    :param command_line_args: Command line arguments to pass when running binary sample in the sandbox
    :param scope: Analysis visibility
    :param tags: Assign tags to an analysis
    :param priority: Priority to processing queue
    :param duplicate: Duplicate an existing binary
    :param symbols: List of functions
    """
    bin_id = re_binary_id(fpath)
    result = re_hash_check(bin_id)

    if result and duplicate is False:
        logger.error("Error, duplicate analysis for %s. To upload again, use the --duplicate flag.",
                     bin_id)
        return

    filename = basename(fpath)

    params = {"file_name": filename, "sha_256_hash": bin_id}

    for p_name in ("model_name", "isa_options", "platform_options", "file_options",
                   "dynamic_execution", "command_line_args", "scope", "tags", "priority", "symbols"):
        p_value = locals()[p_name]

        if p_value:
            params[p_name] = p_value

    res = reveng_req(requests.post, f"analyse", json_data=params)

    if res.status_code == 200:
        logger.info("Successfully submitted binary for analysis. %s - %s", fpath, re_binary_id(fpath))
    elif res.status_code == 400:
        response = res.json()

        if "error" in response.keys():
            logger.warning("Error analysing %s - %s", fpath, response["error"])

    res.raise_for_status()
    return res


def RE_upload(fpath: str) -> Response | bool:
    """
    Upload binary to Server
    :param fpath: File path for binary to analyse
    """
    bin_id = re_binary_id(fpath)
    result = re_hash_check(bin_id)

    if result:
        logger.info("File %s - %s already exists. Skipping upload...", basename(fpath), re_binary_id(fpath))
        return True

    res = reveng_req(requests.post, f"upload", data=open(fpath, "rb").read())

    if res.status_code == 200:
        logger.info("Successfully uploaded binary to your account. %s - %s", fpath, re_binary_id(fpath))
    elif res.status_code == 400:
        response = res.json()

        if "error" in response.keys():
            logger.warning("Error uploading %s - %s", fpath, response["error"])
    elif res.status_code == 413:
        logger.warning("File too large. Please upload files under 100MB.")
    elif res.status_code == 500:
        logger.error("Internal Server Error. Please contact support. Skipping upload...")

    res.raise_for_status()
    return res


def RE_embeddings(fpath: str, binary_id: int = 0) -> Response | None:
    """
    Fetch symbol embeddings
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.get, f"embeddings/{bid}")

    if res.status_code == 400:
        logger.warning("Analysis for %s still in progress. Please check the logs (-l) and try again later.",
                       bin_id)

    res.raise_for_status()
    return res


def RE_signature(fpath: str, binary_id: int = 0) -> Response | None:
    """
    Fetch binary BinNet signature
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.get, f"signature/{bid}")

    if res.status_code == 425:
        logger.warning("Analysis for %s still in progress. Please check the logs (-l) and try again later.",
                       bin_id)

    res.raise_for_status()
    return res


def RE_embedding(fpath: str, start_vaddr: int, end_vaddr: int = None, base_vaddr: int = None,
                 model: str = None) -> Response:
    """
    Fetch embedding for custom symbol range
    :param fpath: File path for binary to analyse
    :param start_vaddr: Start virtual address of the function to extract embeddings
    :param end_vaddr: End virtual address of the function to extract embeddings
    :param base_vaddr: Base address of the binary
    :param model: Binary model name
    """
    params = {}

    if end_vaddr:
        params["end_vaddr"] = end_vaddr
    if base_vaddr:
        params["base_vaddr"] = base_vaddr
    if model:
        params["models"] = model

    bin_id = re_binary_id(fpath)

    res = reveng_req(requests.get, f"embedding/{bin_id}/{start_vaddr}", params=params)

    if res.status_code == 425:
        logger.warning("Analysis for %s still in progress. Please check the logs (-l) and try again later.",
                       bin_id)

    res.raise_for_status()
    return res


def RE_logs(fpath: str, binary_id: int = 0, console: bool = True) -> Response | None:
    """
    Get the logs for an analysis associated to Binary ID in command
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    :param console: Show response in console
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.get, f"logs/{bid}")

    if res.status_code == 200 and console:
        logger.info("Logs found for %s:\n%s", bin_id, res.text)
    elif res.status_code == 404:
        logger.warning("Error, logs not found for %s.", bin_id)

    res.raise_for_status()
    return res


def RE_cves(fpath: str, binary_id: int = 0) -> Response | None:
    """
    Check for known CVEs in Binary
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.get, f"cves/{bid}")

    if res.status_code == 200:
        cves = json.loads(res.text)
        logger.info("Checking for known CVEs embedded inside %s", fpath)

        if len(cves) == 0:
            logger.info("0 CVEs found.")
        else:
            logger.warning("Warning CVEs found!\n%s", res.text)
    elif res.status_code == 404:
        logger.warning(" Error, binary analysis not found for %s.", bin_id)

    res.raise_for_status()
    return res


def RE_status(fpath: str, binary_id: int = 0) -> Response | None:
    """
    Check for known CVEs in Binary
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.get, f"analyse/status/{bid}")

    if res.status_code == 400:
        logger.warning(" Error, status not found for %s.", bin_id)

    res.raise_for_status()
    return res


def RE_compute_distance(embedding: list, embeddings: list, nns: int = 5) -> list:
    """
    Compute the cosine distance between source embedding and embedding from binary
    :param embedding: Embedding vector as python list
    :param embeddings: Symbol embeddings
    :param nns: Number of nearest neighbors
    """
    df = DataFrame(data=embeddings)
    np_embedding = array(embedding).reshape(1, -1)
    source_embeddings = vstack(df["embedding"].values)
    closest = cosine_similarity(source_embeddings, np_embedding).squeeze().argsort()[::-1][:nns]
    distances = cosine_similarity(source_embeddings[closest], np_embedding)

    # match closest embeddings with similarity
    closest_df = df.iloc[closest]

    # create json similarity object
    similarities = list(zip(distances, closest_df.index.tolist()))
    json_sims = [{"similaritiy": float(d[0]), "vaddr": int(df.iloc[v]["vaddr"]), "name": str(df.iloc[v]["name"]),
                  "size": int(df.iloc[v]["size"])} for d, v in similarities]
    return json_sims


def RE_nearest_symbols(embedding: list, model_name: str, nns: int = 5,
                       collections: list = None, ignore_hashes: list = None,
                       distance: float = 0.0, debug_enabled: bool = False) -> Response:
    """
    Get function name suggestions for an embedding
    :param embedding: Embedding vector as python list
    :param model_name: Binary model name
    :param nns: Number of nearest neighbors
    :param collections: List of collections RevEng.AI collection names to search through
    :param ignore_hashes: List[str] SHA-256 hash of binary file to ignore symbols from (usually the current binary)
    :param distance: How close we want the ANN search to filter for
    :param debug_enabled: ANN Symbol Search, only perform ANN on debug symbols if set
    """
    params = {"nns": nns, "model_name": model_name, "debug_enabled": debug_enabled}

    if collections and len(collections) > 0:
        # api param is collection, not collections
        params["collection"] = "|".join(collections)

    if ignore_hashes and len(ignore_hashes) > 0:
        params["ignore_hashes"] = ignore_hashes

    if distance > 0.0:
        params["distance"] = distance

    res = reveng_req(requests.post, "ann/symbol", data=json.dumps(embedding), params=params)

    res.raise_for_status()
    return res


def RE_nearest_binaries(embedding: list, model_name: str, nns: int = 5,
                        collections: list = None, ignore_hashes: list = None) -> Response:
    """
    Get executable suggestions for a binary embedding
    :param embedding: Embedding vector as python list
    :param model_name: Binary model name
    :param nns: Number of nearest neighbors
    :param collections: List of collections RevEng.AI collection names to search through
    :param ignore_hashes: List[str] SHA-256 hash of binary files to ignore symbols from (usually the current binary)
    """
    params = {"nns": nns, "model_name": model_name}

    if collections and len(collections) > 0:
        # api param is collection, not collections
        params["collection"] = "|".join(collections)

    if ignore_hashes and len(ignore_hashes) > 0:
        params["ignore_hashes"] = ignore_hashes

    res = reveng_req(requests.post, "ann/binary", data=json.dumps(embedding), params=params)

    res.raise_for_status()
    return res


def RE_SBOM(fpath: str, binary_id: int = 0) -> Response | None:
    """
    Get Software Bill Of Materials for binary
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res = reveng_req(requests.get, f"sboms/{bid}")

    logger.info("SBOM for %s:\n%s", fpath, res.text)

    res.raise_for_status()
    return res


def RE_functions_rename(function_id: int, new_name: str) -> Response:
    """
    Rename a function.
    :param function_id: ID of a function
    :param new_name: New function name
    """
    res = reveng_req(requests.post, f"functions/rename/{function_id}", json_data={"new_name": new_name})

    logger.info("Function %d has been renamed with %s:\n%s", function_id, new_name, res.text)

    res.raise_for_status()
    return res


def re_binary_id(fpath: str) -> str:
    """
    Take the SHA-256 hash of binary file
    :param fpath: File path for binary to analyse
    """
    if not fpath or not exists(fpath):
        return "undefined"

    hf = sha256()

    with open(fpath, "rb") as f:
        c = f.read()
        hf.update(c)

    return hf.hexdigest()


def _binary_isa(lief_hdlr, exec_type: str) -> str:
    """
    Get executable file format
    """
    if exec_type == "elf":
        machine_type = lief_hdlr.header.machine_type

        if machine_type == ELF.ARCH.i386:
            return "x86"
        elif machine_type == ELF.ARCH.x86_64:
            return "x86_64"
    elif exec_type == "pe":
        machine_type = lief_hdlr.header.machine

        if machine_type == PE.MACHINE_TYPES.I386:
            return "x86"
        elif machine_type == PE.MACHINE_TYPES.AMD64:
            return "x86_64"
    elif exec_type == "macho":
        machine_type = lief_hdlr.header.cpu_type

        if machine_type == MachO.CPU_TYPES.x86:
            return "x86"
        elif machine_type == MachO.CPU_TYPES.x86_64:
            return "x86_64"

    logger.error("Error, failed to determine or unsupported ISA for exec_type: %s.", exec_type)
    raise RuntimeError(f"Error, failed to determine or unsupported ISA for exec_type:{exec_type}.")


def _binary_format(lief_hdlr) -> str:
    """
    Get executable file format
    """
    if lief_hdlr.format == lief_hdlr.format.PE:
        return "pe"
    if lief_hdlr.format == lief_hdlr.format.ELF:
        return "elf"
    if lief_hdlr.format == lief_hdlr.format.MACHO:
        return "macho"

    logger.error("Error, could not determine binary format: %s.", lief_hdlr.format)
    raise RuntimeError("Error, could not determine binary format.")


def file_type(fpath: str) -> tuple[str, str]:
    """
    Determine ISA for binary
    :param fpath: File path for binary to analyse
    """
    binary = parse(fpath)

    # handle PE and ELF files
    file_format = _binary_format(binary)
    isa = _binary_isa(binary, file_format)

    return file_format, isa


def parse_config() -> None:
    """
    Parse ~/.reait.toml config file
    """
    if not exists(expanduser("~/.reait.toml")):
        return

    with open(expanduser("~/.reait.toml"), "r") as file:
        config = tomli.loads(file.read())

        for key in ("apikey", "host", "model"):
            if key in config:
                re_conf[key] = config[key]


def angular_distance(x, y) -> float:
    """
    Compute angular distance between two embedding vectors
    Normalised euclidian distance
    """
    cos = dot(x, y) / ((dot(x, x) * dot(y, y)) ** 0.5)
    return 1.0 - arccos(cos) / pi

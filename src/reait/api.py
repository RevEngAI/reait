from __future__ import print_function, annotations

from os import access, R_OK, environ
from os.path import basename, isfile, expanduser, getsize

import json
import logging
import requests
import tomli
from datetime import datetime
from hashlib import sha256
from lief import parse, Binary, ELF, PE, MachO
from numpy import array, vstack
from pandas import DataFrame
from requests import request, Response, HTTPError
from sklearn.metrics.pairwise import cosine_similarity

__version__ = "1.2.1"

re_conf = {
    "apikey": environ.get("REAI_API_KEY", ""),
    "host": environ.get("REAI_API_HOST", "https://api.reveng.ai"),
}


logger = logging.getLogger("REAIT")


class ReaitError(HTTPError):
    def __init__(self, reason: str, end_point: str = None):
        response = Response()

        response.reason = reason
        response.status_code = 404
        response._content = b'{"success": false, "error": "' + \
            reason.encode() + b'"}'
        response.url = (
            f"{re_conf['host']}/{end_point if end_point[0] != '/' else end_point[1:]}"
            if end_point
            else None
        )

        super().__init__(reason, response=response)


def reveng_req(
    req: request,
    end_point: str,
    data: dict = None,
    ex_headers: dict = None,
    params: dict = None,
    json_data: dict = None,
    timeout: int = 60,
    files: dict = None,
) -> Response:
    """
    Constructs and sends a Request
    :param req: Method for the new Request
    :param end_point: Endpoint to add to the base URL
    :param ex_headers: Extended HTTP headers to add
    :param data: Dictionary, list of tuples, bytes, or file-like object to send in the body
    :param params: Dictionary, list of tuples or bytes to send in the query string for the query string
    :param json_data: A JSON serializable Python object to send in the body
    :param timeout: Number of seconds to stop waiting for a Response
    :param files: Dictionary of files to send to the specified URL
    """
    url = f"{re_conf['host']}/{end_point if end_point[0] != '/' else end_point[1:]}"
    headers = {"Authorization": re_conf["apikey"]}

    if ex_headers:
        headers.update(ex_headers)

    logger.debug(
        "Making %s request %s:\n  - headers: %s\n  - data: %s\n  - json_data: %s\n  - params: %s\n  - files: %s",
        req.__name__.upper(),
        url,
        headers,
        data,
        json_data,
        params,
        files,
    )

    response: Response = req(
        url,
        headers=headers,
        json=json_data,
        data=data,
        params=params,
        timeout=timeout,
        files=files,
    )

    logger.debug(
        "Making %s response %s:\n  - headers: %s\n  - status_code: %d\n  - content: %s",
        req.__name__.upper(),
        url,
        response.headers,
        response.status_code,
        response.text,
    )

    return response


def re_hash_check(bin_id: str) -> bool:
    res: Response = reveng_req(
        requests.get, "v1/search", json_data={"sha_256_hash": bin_id}
    )

    if res.ok:
        return any(
            binary["sha_256_hash"] == bin_id for binary in res.json()["query_results"]
        )
    else:
        logger.warning("Bad Request: %s", res.text)

    return False


# Bin_id is referred to as hash in this program - to maintain usage BID = id of a binary bin_id = hash
# Assumes a file has been passed, correct hash only
# Returns the BID of the binary_id (hash)
def re_bid_search(bin_id: str) -> int:
    res: Response = reveng_req(
        requests.get, "v1/search", json_data={"sha_256_hash": bin_id}
    )

    bid = -1

    if res.ok:
        # Filter the result who matches the SHA-256
        binaries = list(
            filter(
                lambda binary: binary["sha_256_hash"] == bin_id,
                res.json()["query_results"],
            )
        )

        # Check only one record is returned
        if len(binaries) == 1:
            binary = binaries[0]
            bid = binary["binary_id"]

            logger.info(
                "Only one record exists, selecting - ID: %d, Name: %s, Creation: %s, Model: %s, Status: %s",
                bid,
                binary["binary_name"],
                binary["creation"],
                binary["model_name"],
                binary["status"],
            )
        elif len(binaries) > 1:
            binaries.sort(
                key=lambda binary: datetime.fromisoformat(
                    binary["creation"]
                ).timestamp(),
                reverse=True,
            )

            logger.info("%d matches found for hash: %s", len(binaries), bin_id)

            options_dict = {}

            for idx, binary in enumerate(binaries):
                logger.info(
                    "[%d] - ID: %d, Name: %s, Creation: %s, Model: %s, Status: %s",
                    idx,
                    binary["binary_id"],
                    binary["binary_name"],
                    binary["creation"],
                    binary["model_name"],
                    binary["status"],
                )

                options_dict[idx] = binary["binary_id"]

            try:
                user_input = input(
                    "[+] Please enter the option you want to use for this operation:"
                )

                option_number = int(user_input)

                bid = options_dict.get(option_number, -1)

                if bid == -1:
                    logger.warning("Invalid option.")
            except Exception:
                bid = options_dict[0]
                logger.warning("Select the most recent analysis - ID: %d", bid)
        else:
            logger.warning("No matches found for hash: %s", bin_id)
    else:
        logger.warning("Bad Request: %s", res.text)

    res.raise_for_status()
    return bid


def RE_delete(fpath: str, binary_id: int = 0) -> Response:
    """
    Delete analysis results for Binary ID in command
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/analyse/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.delete, end_point)

    if res.ok:
        logger.info("Securely deleted analysis ID %s - %s.", bid, bin_id)
    elif res.status_code == 404:
        logger.warning("Error analysis not found for ID %s - %s.", bid, bin_id)
    else:
        logger.error(
            "Error deleting binary %s under. Server returned %d.",
            bin_id,
            res.status_code,
        )

    res.raise_for_status()
    return res


def RE_analyse(
    fpath: str,
    model_name: str = None,
    isa_options: str = None,
    platform_options: str = None,
    file_options: str = None,
    dynamic_execution: bool = False,
    command_line_args: str = None,
    binary_scope: str = None,
    tags: list = None,
    priority: int = 0,
    duplicate: bool = False,
    symbols: dict = None,
    debug_fpath: str = None,
    skip_scraping: bool = False,
    skip_capabilities: bool = False,
    skip_sbom: bool = False,
    advanced_analysis: bool = False
) -> Response:
    """
    Start analysis job for binary file
    :param fpath: File path for binary to analyse
    :param model_name: Binary model name
    :param isa_options: Executable ISA
    :param file_options: File options
    :param platform_options: OS platform
    :param dynamic_execution: Enable dynamic execution in sandbox during analysis
    :param command_line_args: Command line arguments to pass when running binary sample in the sandbox
    :param binary_scope: Analysis visibility
    :param tags: Assign tags to an analysis
    :param priority: Priority to processing queue
    :param duplicate: Duplicate an existing binary
    :param symbols: JSON object containing the base address and the list of functions
    :param debug_fpath: File path for debug file
    :param skip_scraping: Disable/Enable auto-tagging of binary sample in relevant APIs
    """
    bin_id = re_binary_id(fpath)
    result = re_hash_check(bin_id)

    end_point = "v1/analyse/"

    if result and duplicate is False:
        logger.error(
            "Error, duplicate analysis for %s. To upload again, use the --duplicate flag.",
            bin_id,
        )
        raise ReaitError(f"Duplicate analysis for hash: {bin_id}", end_point)

    filename = basename(fpath)

    params = {
        "file_name": filename,
        "size_in_bytes": getsize(fpath),
        "sha_256_hash": bin_id,
    }

    if debug_fpath and isfile(debug_fpath) and access(debug_fpath, R_OK):
        try:
            debug = RE_upload(debug_fpath).json()

            if debug["success"]:
                params["debug_hash"] = debug["sha_256_hash"]
        except HTTPError:
            pass

    for p_name in (
        "model_name",
        "isa_options",
        "platform_options",
        "file_options",
        "dynamic_execution",
        "command_line_args",
        "binary_scope",
        "tags",
        "priority",
        "symbols",
        "skip_scraping",
        "skip_capabilities",
        "skip_sbom",
        "advanced_analysis"
    ):
        p_value = locals()[p_name]

        if p_value:
            params[p_name] = p_value

    res: Response = reveng_req(requests.post, end_point, json_data=params)
    if res.ok:
        logger.info(
            "Successfully submitted binary for analysis. %s - %s", fpath, bin_id
        )
    elif res.status_code == 400:
        if "error" in res.json().keys():
            logger.warning("Error analysing %s - %s",
                           fpath, res.json()["error"])

    res.raise_for_status()
    return res


def RE_upload(fpath: str) -> Response:
    """
    Upload binary to Server
    :param fpath: File path for binary to analyse
    """
    bin_id = re_binary_id(fpath)
    result = re_hash_check(bin_id)

    if result:
        logger.info(
            "File %s - %s already uploaded. Skipping upload...", fpath, bin_id)

        res = Response()
        res.status_code = 200
        res.url = f"{re_conf['host']}/v1/upload"
        res._content = (
            (
                '{0}"success": true,'
                '"message": "File already uploaded!",'
                '"sha_256_hash": "{1}"{2}'
            )
            .format("{", bin_id, "}")
            .encode()
        )
    else:
        with open(fpath, "rb") as fd:
            res: Response = reveng_req(
                requests.post, "v1/upload", files={"file": fd})

        if res.ok:
            logger.info(
                "Successfully uploaded binary to your account. %s - %s", fpath, bin_id
            )
        elif res.status_code == 400:
            if "error" in res.json().keys():
                logger.warning("Error uploading %s - %s",
                               fpath, res.json()["error"])
        elif res.status_code == 413:
            logger.warning("File too large. Please upload files under 10MB.")
        elif res.status_code == 500:
            logger.error(
                "Internal Server Error. Please contact support. Skipping upload..."
            )

    res.raise_for_status()
    return res


def RE_embeddings(fpath: str, binary_id: int = 0) -> Response:
    """
    Fetch symbol embeddings
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/embeddings/binary/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    if res.status_code == 400:
        logger.warning(
            "Analysis for %s still in progress. Please check the logs (-l) and try again later.",
            bin_id,
        )

    res.raise_for_status()
    return res


def RE_logs(fpath: str, binary_id: int = 0, console: bool = True) -> Response:
    """
    Get the logs for an analysis associated to Binary ID in command
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    :param console: Show response in console
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/logs/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    if res.ok and console:
        logger.info("Logs found for %s:\n%s", bin_id, res.json()["logs"])
    elif res.status_code == 404:
        logger.warning("Error, logs not found for %s.", bin_id)

    res.raise_for_status()
    return res


def RE_cves(fpath: str, binary_id: int = 0) -> Response:
    """
    Check for known CVEs in Binary
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"cves/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    if res.ok:
        cves = json.loads(res.text)
        logger.info("Checking for known CVEs embedded inside %s", fpath)

        if len(cves) == 0:
            logger.info("0 CVEs found.")
        else:
            logger.warning("Warning CVEs found!\n%s", res.text)
    elif res.status_code == 404:
        logger.warning("Error, binary analysis not found for %s.", bin_id)

    res.raise_for_status()
    return res


def RE_status(fpath: str, binary_id: int = 0, console: bool = False) -> Response:
    """
    Get the status of an ongoing binary analysis
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/analyse/status/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    if res.ok and console:
        logger.info("Binary analysis status: %s", res.json()["status"])
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
    closest = (
        cosine_similarity(source_embeddings, np_embedding)
        .squeeze()
        .argsort()[::-1][:nns]
    )
    distances = cosine_similarity(source_embeddings[closest], np_embedding)

    # match closest embeddings with similarity
    closest_df = df.iloc[closest]

    # create json similarity object
    similarities = list(zip(distances, closest_df.index.tolist()))
    json_sims = [
        {
            "similaritiy": float(d[0]),
            "vaddr": int(df.iloc[v]["vaddr"]),
            "name": str(df.iloc[v]["name"]),
            "size": int(df.iloc[v]["size"]),
        }
        for d, v in similarities
    ]
    return json_sims


def RE_nearest_symbols_batch(
    function_ids: list[int],
    nns: int = 5,
    collections: list[int] = None,
    binaries: list[int] = None,
    distance: float = 0.1,
    debug_enabled: bool = False,
) -> Response:
    """
    Get nearest functions to a passed function ids
    :param function_ids: List of function ids
    :param nns: Number of nearest neighbors
    :param collections: List of collections RevEng.AI collection names to search through
    :param distance: How close we want the ANN search to filter for
    :param debug_enabled: ANN Symbol Search, only perform ANN on debug symbols if set
    """
    params = {
        "function_id_list": function_ids,
        "result_per_function": nns,
        "debug_mode": debug_enabled,
        "distance": distance,
    }

    if collections:
        params["collection_search_list"] = collections

    if binaries:
        params["binaries_search_list"] = binaries

    res: Response = reveng_req(
        requests.post, "v1/ann/symbol/batch", json_data=params)

    res.raise_for_status()
    return res


def RE_nearest_functions(
    fpath: str,
    binary_id: int = 0,
    nns: int = 5,
    distance: float = 0.1,
    debug_enabled: bool = False,
) -> Response:
    """
    Get the nearest functions
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    :param nns: Number of nearest neighbors
    :param distance: How close we want the ANN search to filter for
    :param debug_enabled: ANN Symbol Search, only perform ANN on debug symbols if set
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/ann/symbol/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    params = {
        "result_per_function": nns,
        "debug_mode": debug_enabled,
        "distance": distance,
    }

    res: Response = reveng_req(requests.post, end_point, json_data=params)

    res.raise_for_status()
    return res


def RE_analyze_functions(fpath: str, binary_id: int = 0) -> Response:
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/analyse/functions/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    res.raise_for_status()
    return res


def RE_SBOM(fpath: str, binary_id: int = 0) -> Response:
    """
    Get Software Bill Of Materials for binary
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"sboms/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    logger.info("SBOM for %s:\n%s", fpath, res.text)

    res.raise_for_status()
    return res


def RE_binary_additonal_details(fpath: str, binary_id: int = None) -> Response:
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id is None else binary_id
    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}")

    endpoint = f"v2/binaries/{bid}/additional-details"
    res: Response = reveng_req(requests.get, endpoint)
    res.raise_for_status()

    logger.info(f"Additional Details Info({fpath}):\n")
    logger.info(f"\n{json.dumps(res.json(), indent=4)}")
    return res


def RE_binary_details(fpath: str, binary_id: int = None) -> Response:
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id is None else binary_id
    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}")

    endpoint = f"v2/binaries/{bid}/details"
    res: Response = reveng_req(requests.get, endpoint)
    res.raise_for_status()

    logger.info(f"Details Info({fpath}):\n")
    logger.info(f"\n{json.dumps(res.json(), indent=4)}")
    return res


def RE_functions_rename(function_id: int, new_name: str) -> Response:
    """
    Send the new name of a function to C2
    :param function_id: ID of a function
    :param new_name: New function name
    """
    res: Response = reveng_req(
        requests.post,
        f"v1/functions/rename/{function_id}",
        json_data={"new_name": new_name},
    )

    if res.ok:
        logger.info("FunctionId %d has been renamed with '%s'.",
                    function_id, new_name)
    else:
        logger.warning("Error, cannot rename FunctionId %d. %s",
                       function_id, res.text)

    res.raise_for_status()
    return res


def RE_functions_rename_batch(mapping: dict[int, str]) -> Response:
    """
    Send a list of dictionaries, with a corresponding key as function ID and the desired function_name
    :param mapping: dictionary containing the function_id as key and function_name as value
    """
    params = {
        "new_name_mapping": [
            {
                "function_id": func_id,
                "function_name": func_name,
            }
            for func_id, func_name in mapping.items()
        ]
    }

    res: Response = reveng_req(
        requests.post, "v1/functions/batch/rename", json_data=params
    )

    res.raise_for_status()
    return res


def RE_settings() -> Response:
    """
    Get the configuration settings
    """
    res: Response = reveng_req(requests.get, "v1/config")

    res.raise_for_status()
    return res


def RE_health() -> bool:
    """
    Health check & verify access to the API
    """
    res: Response = reveng_req(requests.get, "v1")

    success = res.json()["success"]

    if success:
        logger.info(res.json()["message"])
    else:
        logger.warning(res.json()["error"])
    return success


def RE_authentication() -> Response:
    """
    Authentication Check
    """
    res: Response = reveng_req(requests.get, "v1/authenticate")

    res.raise_for_status()
    return res


def RE_functions_list(
    analysis_id: int,
    search_term: str = "",
    min_v_address: int = 0,
    max_v_address: int = 0,
) -> Response:
    """
    Get the functions of a binary
    :param binary_id: Binary ID
    """
    params = {}
    if search_term:
        params["search_term"] = search_term

    if min_v_address != 0:
        params["min_v_address"] = min_v_address

    if max_v_address != 0:
        params["max_v_address"] = max_v_address

    res: Response = reveng_req(
        requests.get,
        f"/v2/analyses/{analysis_id}/functions/list",
        params=params
    )

    res.raise_for_status()

    return res


def RE_function_callers_callees(function: int) -> Response:
    """
    Get the callers and callees of a functions
    :param function: Function ID
    """
    res: Response = reveng_req(
        requests.get, f"v2/functions/{function}/callees_callers")

    res.raise_for_status()
    return res


def RE_analysis_info(analysis_id: int) -> Response:
    """
    Get the analysis information
    :param analysis_id: Analysis ID
    """
    res: Response = reveng_req(
        requests.get, f"v2/analyses/{analysis_id}/info/basic")

    res.raise_for_status()
    return res


def re_binary_id(fpath: str) -> str:
    """
    Take the SHA-256 hash of binary file
    :param fpath: File path for binary to analyse
    """
    if fpath and isfile(fpath) and access(fpath, R_OK):
        hf = sha256()

        with open(fpath, "rb") as fd:
            c = fd.read()
            hf.update(c)

        return hf.hexdigest()
    else:
        return fpath


def _binary_isa(binary: Binary, exec_type: str) -> str:
    """
    Get ISA format
    """
    if exec_type == "ELF":
        arch = binary.header.machine_type
        if arch == ELF.ARCH.I386:
            return "x86"
        elif arch == ELF.ARCH.X86_64:
            return "x86_64"
        elif arch == ELF.ARCH.ARM:
            return "ARM32"
        elif arch == ELF.ARCH.AARCH64:
            return "ARM64"
    elif exec_type == "PE":
        machine_type = binary.header.machine
        if machine_type == PE.Header.MACHINE_TYPES.I386:
            return "x86"
        elif machine_type == PE.Header.MACHINE_TYPES.AMD64:
            return "x86_64"
        elif machine_type == PE.Header.MACHINE_TYPES.ARM:
            return "ARM32"
        elif machine_type == PE.Header.MACHINE_TYPES.ARM64:
            return "ARM64"
    elif exec_type == "Mach-O":
        cpu_type = binary.header.cpu_type

        if cpu_type == MachO.Header.CPU_TYPE.X86:
            return "x86"
        elif cpu_type == MachO.Header.CPU_TYPE.X86_64:
            return "x86_64"
        elif cpu_type == MachO.Header.CPU_TYPE.ARM:
            return "ARM32"
        elif cpu_type == MachO.Header.CPU_TYPE.ARM64:
            return "ARM64"

    logger.error(
        "Error, could not determine or unsupported "
        f"ISA for binary format: {exec_type}."
    )
    raise RuntimeError(
        "Error, could not determine or unsupported "
        f"ISA for binary format: {exec_type}."
    )


def _binary_format(binary: Binary) -> str:
    """
    Get executable file format
    """
    if binary.format == Binary.FORMATS.PE:
        return "PE"
    if binary.format == Binary.FORMATS.ELF:
        return "ELF"
    if binary.format == Binary.FORMATS.MACHO:
        return "Mach-O"

    logger.error(
        "Error, could not determine or unsupported"
        f" binary format: {binary.format}."
    )
    raise RuntimeError(
        "Error, could not determine or "
        f"unsupported binary format: {binary.format}"
    )


def file_type(fpath: str) -> tuple[str, str]:
    """
    Determine ISA for binary
    :param fpath: File path for binary to analyse
    """
    binary = parse(fpath)

    if not binary:
        file_format = isa_format = "Unknown format"
    else:
        # handle PE and ELF files
        file_format = _binary_format(binary)
        isa_format = _binary_isa(binary, file_format)

    return file_format, isa_format


def parse_config() -> None:
    """
    Parse ~/.reait.toml config file
    """
    fpath = expanduser("~/.reait.toml")

    if isfile(fpath) and access(fpath, R_OK):
        with open(fpath) as fd:
            config = tomli.loads(fd.read())

            for key in (
                "apikey",
                "host",
                "model",
            ):
                if key in config:
                    re_conf[key] = config[key]
    else:
        logger.info("File %s doesn't exist or isn't readable", fpath)


def RE_analysis_id(fpath: str, binary_id: int = 0) -> Response:
    """
    Get the Analysis ID for the Binary ID
    :param fpath: File path for binary to analyse
    :param binary_id: ID of binary
    """
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v2/analyses/lookup/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(requests.get, end_point)

    logger.info("Analysis ID for %s:\n%s", fpath, res.text)

    res.raise_for_status()
    return res


def RE_functions_data_types(
    function_ids: list[int],
) -> Response:
    """
    Get data types for the functions
    :param functions_ids: List of function IDs
    :return: Response object
    """
    endpoint = "/v2/functions/data_types"
    res: Response = reveng_req(
        requests.post, endpoint, json_data={"function_ids": function_ids}
    )
    res.raise_for_status()
    return res


def RE_functions_data_types_poll(
    function_ids: list[int],
) -> Response:
    """
    Poll data types for the functions
    :param functions_ids: List of function IDs
    :return: Response object
    """
    endpoint = "/v2/functions/data_types"
    res: Response = reveng_req(
        requests.get, endpoint, params={"function_ids": function_ids}
    )
    res.raise_for_status()
    return res


def RE_generate_data_types(
    analysis_id: int,
    function_ids: list[int]
) -> Response:
    """
    Generate data types for the analysis
    :param aid: Analysis ID
    """
    end_point = f"/v2/analyses/{analysis_id}/functions/data_types"

    res: Response = reveng_req(
        requests.post, end_point, json_data={"function_ids": function_ids}
    )
    res.raise_for_status()
    return res


def RE_poll_data_types(
    analysis_id: int,
    function_id: int,
) -> Response:
    """
    Poll data types for the analysis
    :param aid: Analysis ID
    """
    end_point = f"/v2/analyses/{analysis_id}/functions/{function_id}/data_types"

    res: Response = reveng_req(requests.get, end_point)
    res.raise_for_status()
    return res


def RE_list_data_types(analysis_id: int, function_ids: list[int]) -> Response:
    """
    List data types for the analysis
    :param aid: Analysis ID
    :param function_ids: List of function IDs
    """
    end_point = f"/v2/analyses/{analysis_id}/functions/data_types"

    res: Response = reveng_req(
        requests.get, end_point, json_data={"function_ids": function_ids}
    )
    res.raise_for_status()
    return res


def RE_begin_ai_decompilation(function_id: int) -> Response:
    """
    Begin AI decompilation for the function
    :param function_id: Function ID
    """
    end_point = f"/v2/functions/{function_id}/ai-decompilation"

    res: Response = reveng_req(
        requests.post,
        end_point,
        data=None,
    )
    res.raise_for_status()
    return res


def RE_poll_ai_decompilation(
    function_id: int,
    summarise: bool = False
) -> Response:
    """
    Poll AI decompilation for the function
    :param function_id: Function ID
    """
    end_point = f"/v2/functions/{function_id}/ai-decompilation"

    params = {}

    if summarise:
        params["summarise"] = summarise

    res: Response = reveng_req(
        requests.get,
        end_point,
        params=params,
    )
    res.raise_for_status()
    return res


def RE_analysis_lookup(binary_id: int) -> Response:
    """
    Get the Analysis ID from a Binary ID
    :param binary_id: Binary ID
    """
    end_point = f"/v2/analyses/lookup/{binary_id}"
    res: Response = reveng_req(requests.get, end_point)
    res.raise_for_status()
    return res


def RE_collections_search(
        page: int = 1,
        page_size: int = 10,
        query: dict = {},
) -> Response:
    """
    Search for collections in the database
    """
    end_point = "/v2/search/collections"
    params = {
        "page": page,
        "page_size": page_size,
    }

    # this api support:
    #   partial_collection_name
    #   partial_binary_name
    #   partial_binary_sha256
    #   model_name
    #   tags

    def exist_and_populated(key: str) -> bool:
        return key in query and query[key] is not None and len(query[key]) > 0

    if exist_and_populated("collection_name"):
        params["partial_collection_name"] = query["collection_name"]
    elif exist_and_populated("binary_name"):
        params["partial_binary_name"] = query["binary_name"]
    elif exist_and_populated("sha_256_hash"):
        params["partial_binary_sha256"] = query["sha_256_hash"]
    elif exist_and_populated("tags"):
        params["tags"] = query["tags"]
    elif exist_and_populated("model_name"):
        params["model_name"] = query["model_name"]
    elif exist_and_populated("query"):
        params["partial_collection_name"] = query["query"]

    res: Response = reveng_req(requests.get, end_point, params=params)
    res.raise_for_status()
    return res


def RE_binaries_search(
        page: int = 1,
        page_size: int = 10,
        query: dict = {},
) -> Response:
    """
    Search for binaries in the database
    """
    end_point = "/v2/search/binaries"
    params = {
        "page": page,
        "page_size": page_size,
    }

    # this api support:
    #   partial_name
    #   partial_sha256
    #   tags
    #   model_name

    def exist_and_populated(key: str) -> bool:
        return key in query and query[key] is not None and len(query[key]) > 0

    if exist_and_populated("binary_name"):
        params["partial_name"] = query["binary_name"]
    elif exist_and_populated("sha_256_hash"):
        params["partial_sha256"] = query["sha_256_hash"]
    elif exist_and_populated("tags"):
        params["tags"] = query["tags"]
    elif exist_and_populated("model_name"):
        params["model_name"] = query["model_name"]
    elif exist_and_populated("query"):
        params["partial_name"] = query["query"]

    res: Response = reveng_req(requests.get, end_point, params=params)
    res.raise_for_status()
    return res


# Bin_id is referred to as hash in this program - to maintain usage BID = id
# of a binary bin_id = hash
# Assumes a file has been passed, correct hash only
# Returns the BID of the binary_id (hash)
def RE_latest_bid(bin_id: str) -> int:
    res: Response = reveng_req(
        requests.get, "v1/search", json_data={"sha_256_hash": bin_id}
    )

    bid = -1

    if res.ok:
        # Filter the result who matches the SHA-256
        binaries = list(
            filter(
                lambda binary: binary["sha_256_hash"] == bin_id,
                res.json()["query_results"],
            )
        )

        # Check only one record is returned
        if len(binaries) == 1:
            binary = binaries[0]
            bid = binary["binary_id"]

            logger.info(
                "Only one record exists, selecting - ID: %d, Name: %s, Creation: %s, Model: %s, Status: %s",
                bid,
                binary["binary_name"],
                binary["creation"],
                binary["model_name"],
                binary["status"],
            )
        elif len(binaries) > 1:
            binaries.sort(
                key=lambda binary: datetime.fromisoformat(
                    binary["creation"]
                ).timestamp(),
                reverse=True,
            )

            logger.info("%d matches found for hash: %s", len(binaries), bin_id)

            options_dict = {}

            for idx, binary in enumerate(binaries):
                logger.info(
                    "[%d] - ID: %d, Name: %s, Creation: %s, Model: %s, Status: %s",
                    idx,
                    binary["binary_id"],
                    binary["binary_name"],
                    binary["creation"],
                    binary["model_name"],
                    binary["status"],
                )

                options_dict[idx] = binary["binary_id"]
            try:
                bid = options_dict[0]
            except Exception:
                bid = options_dict[0]
                logger.warning("Select the most recent analysis - ID: %d", bid)
        else:
            logger.warning("No matches found for hash: %s", bin_id)
    else:
        logger.warning("Bad Request: %s", res.text)

    res.raise_for_status()
    return bid


# NOTE: newest API as per documentation still using /v1/ prefix
def RE_models() -> Response:
    res: Response = reveng_req(requests.get, "v1/models")

    res.raise_for_status()
    return res


# NOTE: newest API as per documentation still using /v1/ prefix
def RE_functions_dump(function_ids: list[int]) -> Response:
    res: Response = reveng_req(
        requests.post, "v1/functions/dump", json_data={"function_id_list": function_ids}
    )

    res.raise_for_status()
    return res


# NOTE: this API endpoint does not actually exist
def RE_generate_summaries(function_id: int) -> Response:
    res: Response = reveng_req(
        requests.get, f"v1/functions/blocks_comments/{function_id}"
    )

    res.raise_for_status()
    return res


def RE_collection_search(search: str) -> Response:
    res: Response = reveng_req(
        requests.get,
        "v1/collections/quick/search",
        params={"search_term": search if search else ""},
    )

    res.raise_for_status()
    return res


def RE_recent_analysis(
    status: str = "All", scope: str = "ALL", nb_analysis: int = 50
) -> Response:
    res: Response = reveng_req(
        requests.get,
        "v1/analyse/recent",
        json_data={"status": status, "scope": scope, "n": nb_analysis},
    )

    res.raise_for_status()
    return res


def RE_search(fpath: str) -> Response:
    bin_id = re_binary_id(fpath)

    res: Response = reveng_req(
        requests.get, "v1/search", json_data={"sha_256_hash": bin_id}
    )

    res.raise_for_status()
    return res


# NOTE: this uses a newer API version
def RE_similar_functions(
    function_id: int,
    limit: int = 20,
    distance: int | float = 0.09999999999999998,
    debug: bool = False,
):
    params = {
        "distance": distance,
        "limit": limit,
        "debug": debug,
    }

    res: Response = reveng_req(
        requests.get, f"v2/functions/{function_id}/similar-functions", params=params
    )

    res.raise_for_status()
    return res

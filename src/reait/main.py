#!/usr/bin/env python3
from __future__ import print_function

from sys import exit, stdout, stderr

import argparse
import json
import logging
import numpy as np
import os
from glob import iglob
from pathlib import Path
from requests import HTTPError
from rich import print_json
from rich.console import Console
from rich.progress import track
from scipy.spatial import distance
from typing import Optional
from reait import api

rerr = Console(file=stderr, width=180)
rout = Console(file=stdout, width=180)


def version() -> int:
    """
    Display program version
    """
    rout.print(
        f"""[bold blue] ::::::::    ::::::::
::  ::::    :::  :::
::::::::::::::::::::
:::::   :::   ::::::
   ::::::::::::::   
   .::  :::  ::::   
::::::  :::  :::::::
::  :::::::::::  :::
::  :::::  ::::  :::
::::::::    :::::::: [/bold blue]
  [bold red]reait[/bold red] [bold bright_green]v{api.__version__}[/bold bright_green]
"""
    )
    rout.print("[yellow]Config:[/yellow]")
    print_json(data=api.re_conf)
    return 0


def verify_binary(fpath_fmt: str) -> tuple[str, str, str]:
    fpath = fpath_fmt

    exec_format, exec_isa = api.file_type(fpath)

    return fpath, exec_format, exec_isa


def match(
    fpath: str, embeddings: list, confidence: float = 0.95, deviation: float = 0.1
) -> None:
    """
    Match embeddings in fpath from a list of embeddings
    """
    rout.print(f"Matching symbols from {fpath} with confidence {confidence}.")
    sink_embed_mat = np.vstack(list(map(lambda x: x["embedding"], embeddings)))
    b_embeds = api.RE_embeddings(fpath).json()["data"]
    source_embed_mat = np.vstack(list(map(lambda x: x["embedding"], b_embeds)))
    # angular distance over cosine
    # closest = 1.0 - distance.cdist(source_embed_mat, sink_embed_mat, 'cosine')
    closest = distance.cdist(source_embed_mat, sink_embed_mat, api.angular_distance)
    # rescale to separate high end of (-1, 1.0)
    # closest = rescale_sim(closest)
    i, j = closest.shape

    for _i in track(range(i), description="Matching Symbols..."):
        row = closest[_i, :]
        match_index, second_match = row.argsort()[::-1][:2]
        source_index = _i
        sink_index = match_index
        source_symb = b_embeds[_i]
        sink_symb = embeddings[sink_index]
        m_confidence = row[match_index]
        s_confidence = row[second_match]

        if row[match_index] >= confidence:
            rout.print(
                f"[bold green]Found match![/bold green][yellow]\tConfidence: {m_confidence:.05f}[/yellow]\t"
                f"[blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t"
                f"[blue]{sink_symb['name']}:{sink_symb['vaddr']}"
            )
        elif (m_confidence - s_confidence) > deviation:
            rout.print(
                f"[bold magenta]Possible match[/bold magenta][yellow]\t"
                f"Confidence: {m_confidence:.05f}/{s_confidence:.05f}[/yellow]\t"
                f"[blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t"
                f"[blue]{sink_symb['name']}:{sink_symb['vaddr']}"
            )
        else:
            rerr.print(
                f"[bold red]No match for[/bold red]\t[blue]{source_symb['name']}:{source_symb['vaddr']}\t"
                f"{sink_symb['name']} - {m_confidence:0.05f}[/blue]"
            )
            pass


def match_for_each(fpath: str, confidence: float = 0.9, nns: int = 1) -> int:
    """
    Match embeddings in fpath from a list of embeddings
    """
    nns = max(nns, 1)

    rout.print(
        f"Matching symbols from '{fpath}' with a confidence {confidence:.02f} and up to "
        f"{nns} result{'' if nns == 1 else 's'} per function"
    )
    functions = api.RE_analyze_functions(fpath).json()["functions"]
    function_matches = api.RE_nearest_functions(
        fpath, nns=nns, distance=1 - confidence
    ).json()["function_matches"]

    if len(function_matches) == 0:
        rerr.print(
            f"[bold red]No matches found for a confidence of [/bold red] {confidence:.02f}"
        )
        return -1
    else:
        for function in functions:
            matches = list(
                filter(
                    lambda x: function["function_id"] == x["origin_function_id"],
                    function_matches,
                )
            )

            if len(matches):
                rout.print(
                    f"[bold green]Found {len(matches)} match{'' if len(matches) == 1 else 'es'} for "
                    f"[/bold green][blue]{function['function_name']}: {function['function_vaddr']:#x}[/blue]"
                )

                for match in matches:
                    rout.print(
                        f"\t[yellow]Confidence: {match['confidence']:.05f}[/yellow]"
                        f"\t[blue]{match['nearest_neighbor_function_name']}"
                        f" ({match['nearest_neighbor_binary_name']})[/blue]"
                    )
            else:
                rout.print(
                    f"[bold red]No matches found for[/bold red] "
                    f"[blue]{function['function_name']}: {function['function_vaddr']:#x}[/blue]"
                )
    return 0


def parse_collections(collections: str) -> Optional[list[str]]:
    """
    Return collections as list from CSV
    """
    if not collections:
        return None
    return collections.split(",")


def rescale_sim(x):
    """
    Too many values close to 0.999, 0.99999, 0.998, rescale so small values are very low,
    high values separated, map to hyperbolic space
    """
    return np.power(x, 5)


def validate_file(arg):
    file = Path(arg)
    if file.is_file():
        return file.absolute()
    raise FileNotFoundError(f"File path {arg} does not exists.")


def validate_dir(arg):
    dir = Path(arg)
    if dir.is_dir():
        return dir.absolute()
    raise NotADirectoryError(f"Directory path {arg} does not exists.")


def report_api_error_message(f):
    """
    Print message from API errors to console
    """

    def decorate(f):
        def applicator(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except HTTPError as err:
                content = err.response.json()
                if "message" in content:
                    rerr.print(
                        f"[bold red]API Error[/bold red] [bold blue_violet]{err.response.status_code}[/bold blue_violet][bold red] to [/bold red][bold yellow]{err.response.url}[/bold yellow][bold red] {err.response.json()['message']}[/bold red]"
                    )
                    if "errors" in content:
                        for msg in content["errors"]:
                            rerr.print(f"[bold red]{msg['message']}[/bold red]")

                    exit()

        return applicator

    return decorate(f)


@report_api_error_message
def main() -> int:
    """
    Tool entry
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-b",
        "--binary",
        type=validate_file,
        help="Path of binary to analyse, use ./path:{exec_format} to specify executable format e.g. ./path:raw-x86_64",
    )
    parser.add_argument(
        "-B",
        "--binary-hash",
        default="",
        help="Hex-encoded SHA-256 hash of the binary to use",
    )
    parser.add_argument(
        "-D",
        "--dir",
        type=validate_dir,
        help="Path of directory to recursively analyse",
    )
    parser.add_argument(
        "-a",
        "--analyse",
        action="store_true",
        help="Perform a full analysis and generate embeddings for every symbol",
    )
    parser.add_argument(
        "--base-address",
        help="Image base of the executable image to map for remote analysis",
    )
    parser.add_argument(
        "-A", action="store_true", help="Upload and Analyse a new binary"
    )
    parser.add_argument(
        "-u",
        "--upload",
        action="store_true",
        help="Upload a new binary to remote server",
    )
    parser.add_argument(
        "--duplicate",
        default=False,
        action="store_true",
        help="Duplicate an existing binary",
    )
    parser.add_argument(
        "--details",
        default=False,
        action="store_true",
        help="Get binary additional details",
    )
    parser.add_argument(
        "-e", "--embedding", help="Path of JSON file containing a BinNet embedding"
    )
    parser.add_argument(
        "--nns",
        default="5",
        help="Number of approximate nearest neighbors to fetch",
        type=int,
    )
    parser.add_argument(
        "--collections",
        default=None,
        help="Comma Seperated Value of collections to search from e.g. libxml2,libpcap. Used to select RevEng.AI collections for filtering search results",
    )
    parser.add_argument(
        "--found-in",
        help="ANN flag to limit to embeddings returned to those found in specific binary",
    )
    parser.add_argument(
        "--from-file",
        help="ANN flag to limit to embeddings returned to those found in JSON embeddings file",
    )
    parser.add_argument(
        "-c", "--cves", action="store_true", help="Check for CVEs found inside binary"
    )
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM for binary")
    parser.add_argument(
        "-m", "--model", default=None, help="AI model used to generate embeddings"
    )
    parser.add_argument(
        "-x", "--extract", action="store_true", help="Fetch embeddings for binary"
    )
    parser.add_argument(
        "-M",
        "--match",
        action="store_true",
        help="Match functions in binary file. Can be used with --confidence, --deviation, --from-file, --found-in.",
    )
    parser.add_argument(
        "--confidence",
        default="high",
        choices=["high", "medium", "low", "partial", "all"],
        help="Confidence threshold used to match symbols. Valid values are 'all', 'medium', 'low', 'partial' or 'high'[DEFAULT]",
    )
    parser.add_argument(
        "--deviation",
        default=0.1,
        type=float,
        help="Deviation in prediction confidence between outlier and next highest symbol. Use if confident symbol is present in binary but not matching.",
    )
    parser.add_argument(
        "-l", "--logs", action="store_true", help="Fetch analysis log file for binary"
    )
    parser.add_argument(
        "-d",
        "--delete",
        action="store_true",
        help="Delete all metadata associated with binary",
    )
    parser.add_argument("-k", "--apikey", help="RevEng.AI Personal API key")
    parser.add_argument("-h", "--host", help="Analysis Host (https://api.reveng.ai)")
    parser.add_argument(
        "-v", "--version", action="store_true", help="Display version information"
    )
    parser.add_argument(
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help=argparse._("Show this help message and exit"),
    )
    parser.add_argument(
        "--isa",
        default=None,
        help="Override executable ISA. Valid values are x86, x86_64, ARMv7",
    )
    parser.add_argument(
        "--exec-format",
        default=None,
        help="Override executable format. Valid values are pe, elf, macho, raw",
    )
    parser.add_argument(
        "--platform",
        default=None,
        help="Override OS platform. Valid values are Windows, Linux, OSX, OpenBSD",
    )
    parser.add_argument(
        "--dynamic-execution",
        default=False,
        action="store_true",
        help="Enable dynamic execution in sandbox during analysis. Analysis will include any auto unpacked malware samples",
    )
    parser.add_argument(
        "--cmd-line-args",
        default="",
        help="Command line arguments to pass when running binary sample in the sandbox. Only used when run with --dynamic-execution",
    )
    parser.add_argument(
        "--scope",
        default="private",
        choices=["public", "private"],
        help="Override analysis visibility (scope). Valid values are 'public' or 'private'[DEFAULT]",
    )
    parser.add_argument(
        "--tags",
        default=None,
        type=str,
        help="Assign tags to an analysis. Valid responses are tag1,tag2,tag3.",
    )
    parser.add_argument(
        "--do-not-auto-tag",
        default=False,
        action="store_true",
        help="Disable auto-tagging in API views",
    )
    parser.add_argument(
        "--priority", default=0, type=int, help="Add priority to processing queue."
    )
    parser.add_argument(
        "--verbose", default=False, action="store_true", help="Set verbose output."
    )
    parser.add_argument(
        "--debug", default=None, help="Debug file path to write pass with analysis"
    )
    parser.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="Ongoing status of the provided binary",
    )

    args = parser.parse_args()

    # set re_conf args
    for arg in (
        "apikey",
        "host",
        "model",
    ):
        if getattr(args, arg):
            api.re_conf[arg] = getattr(args, arg)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    # display version and exit
    if args.version:
        return version()

    # validate length of string tags
    tags = None
    if args.tags:
        tags = parse_collections(args.tags)

    collections = None
    if args.collections:
        collections = parse_collections(args.collections)

    # auto analysis, uploads and starts analysis
    if args.A:
        args.upload = args.analyse = True

    if args.dir:
        files = iglob(os.path.abspath(args.dir) + "/**/*", recursive=True)
        # perform operation on all files inside directory
        for file in track(files, description="Files in directory"):
            if not os.path.isfile(file):
                rerr.print(f"[blue]Skipping non-file:[/blue] {file}")
                continue

            # upload binary
            if args.upload:
                api.RE_upload(file)

            if args.analyse:
                try:
                    fpath, exec_fmt, exec_isa = verify_binary(file)
                    rout.print(f"Found {fpath}: {exec_fmt}-{exec_isa}")
                except Exception as e:
                    rerr.print(
                        f"[red bold][!] Error, binary exec type could not be verified:[/red bold] {file}"
                    )
                    rerr.print(f"[yellow] {e} [/yellow]")

                rout.print(f"[green bold]Analysing:[/green bold] {file}")
                api.RE_analyse(
                    file,
                    model_name=api.re_conf["model"],
                    isa_options=args.isa,
                    platform_options=args.platform,
                    dynamic_execution=args.dynamic_execution,
                    command_line_args=args.cmd_line_args,
                    file_options=args.exec_format,
                    binary_scope=args.scope.upper(),
                    tags=tags,
                    priority=args.priority,
                    duplicate=args.duplicate,
                    debug_fpath=args.debug,
                    skip_scraping=args.do_not_auto_tag,
                )

            if args.delete:
                try:
                    rout.print(
                        f"[green bold]Deleting analyses for:[/green bold] {file}"
                    )
                    api.RE_delete(file)
                except Exception as e:
                    rerr.print(
                        f"[red bold][!] Error, could not delete analysis for:[/red bold] {file}"
                    )
                    rerr.print(f"[yellow] {e} [/yellow]")

            if not (args.upload or args.analyse or args.delete):
                rerr.print(
                    f"Error, '-D' flag only supports upload, analyse, or delete."
                )
                return -1
    elif (
        args.analyse
        or args.extract
        or args.logs
        or args.delete
        or args.details
        or args.upload
        or args.match
        or args.cves
        or args.sbom
        or args.status
    ):
        try:
            fpath, exec_fmt, exec_isa = verify_binary(args.binary)
            # keep stdout to data only
            rout.print(f"Found {fpath}: {exec_fmt}-{exec_isa}")
            args.binary = fpath
        except TypeError as e:
            rerr.print(
                "[bold red][!] Error, please supply a valid binary file using '-b' flag.[/bold red]"
            )
            rerr.print(f"[yellow] {e} [/yellow]")
            return 0
        except Exception as e:
            rerr.print(
                f"[bold red][!] Error, binary exec type could not be verified:[/bold red] {args.binary}"
            )
            rerr.print(f"[yellow] {e} [/yellow]")

        if args.upload:
            api.RE_upload(args.binary)

            if not args.analyse:
                return 0

        # upload binary first, them carry out actions
        if args.analyse:
            api.RE_analyse(
                args.binary,
                model_name=api.re_conf["model"],
                isa_options=args.isa,
                platform_options=args.platform,
                dynamic_execution=args.dynamic_execution,
                command_line_args=args.cmd_line_args,
                file_options=args.exec_format,
                binary_scope=args.scope.upper(),
                tags=tags,
                priority=args.priority,
                duplicate=args.duplicate,
                debug_fpath=args.debug,
                skip_scraping=args.do_not_auto_tag,
            )

        elif args.extract:
            embeddings = api.RE_embeddings(args.binary).json()
            print_json(data=embeddings)

        elif args.match:
            # parse confidences
            confidence: float = 0.90
            if args.confidence:
                confidences = {
                    "high": 0.95,
                    "medium": 0.9,
                    "low": 0.7,
                    "partial": 0.5,
                    "all": 0.0,
                }
                if args.confidence in confidences.keys():
                    confidence = confidences[args.confidence]

            if args.from_file:
                if not os.path.isfile(args.from_file) and not os.access(
                    args.from_file, os.R_OK
                ):
                    rerr.print(
                        "[bold red][!] Error, '--from-file' flag requires a path to a JSON embeddings file.[/bold red]"
                    )
                    return -1
                rout.print(
                    f"[+] Searching for symbols similar to embedding in binary: {args.from_file}"
                )
                embeddings = json.load(open(args.from_file))
            elif args.found_in:
                if not os.path.isfile(args.found_in) and not os.access(
                    args.found_in, os.R_OK
                ):
                    rerr.print(
                        "[bold red][!] Error, '--found-in' flag requires a path to a binary to search from.[/bold red]"
                    )
                    return -1
                rout.print(
                    f"[+] Matching symbols between {args.binary} and {args.found_in}."
                )
                embeddings = api.RE_embeddings(args.found_in).json()["data"][
                    "embedding"
                ]
            else:
                return match_for_each(args.binary, confidence, args.nns)

            match(
                args.binary,
                embeddings,
                confidence=confidence,
                deviation=float(args.deviation),
            )

        elif args.logs:
            api.RE_logs(args.binary)

        elif args.delete:
            api.RE_delete(args.binary)

        elif args.sbom:
            api.RE_SBOM(args.binary)

        elif args.cves:
            api.RE_cves(args.binary)
        elif args.details:
            api.RE_binary_additonal_details(args.binary)

        elif args.status:
            api.RE_status(args.binary, console=True)

    else:
        rerr.print("[bold red][!] Error, please supply an action command.[/bold red]")
        parser.print_help()
    return 0


if __name__ == "__main__":
    exit(main())

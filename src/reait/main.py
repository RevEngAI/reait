#!/usr/bin/env python
from __future__ import print_function

import logging

from rich import print_json
from rich.progress import track
from rich.console import Console
from rich.table import Table
import os
import argparse
import json
from os.path import isfile, getsize
from sys import exit, stdout, stderr
from reait import api, __version__
from scipy.spatial import distance
from glob import iglob
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count

rerr = Console(file=stderr)
rout = Console(file=stdout)


def version():
    """
        Display program version
    """
    rout.print(f"""[bold blue] ::::::::    ::::::::
::  ::::    :::  :::
::::::::::::::::::::
:::::   :::   ::::::
   ::::::::::::::   
   .::  :::  ::::   
::::::  :::  :::::::
::  :::::::::::  :::
::  :::::  ::::  :::
::::::::    :::::::: [/bold blue]
  [bold red]reait[/bold red] [bold bright_green]v{__version__}[/bold bright_green]
""")
    rout.print("[yellow]Config:[/yellow]")
    print_json(data=api.re_conf)


def verify_binary(fpath_fmt: str):
    fmt = None
    fpath = fpath_fmt

    # if ':' in fpath_fmt:
    #    fpath, fmt = fpath_fmt.split(':')

    if not os.path.isfile(fpath):
        raise RuntimeError(f"File path {fpath} is not a file")

    # if getsize(fpath) > 1024 * 1024 * 10:
    #    raise RuntimeError("Refusing to analyse file over 10MB. Please use a RevEng.AI SRE integration")

    if not fmt:
        exec_format, exec_isa = api.file_type(fpath)
    elif '-' not in fmt:
        raise RuntimeError(
            'Binary type must follow format {EXEC_FORMAT}-{ISA}. Use EXEC_FORMAT raw for memory dumps e.g. raw-x86')
    else:
        exec_format, exec_isa = fmt.split('-')

    return fpath, exec_format, exec_isa


def match(fpath: str, model_name: str, embeddings: list, confidence: float = 0.95, deviation: float = 0.1):
    """
    Match embeddings in fpath from a list of embeddings
    """
    print(f"Matching symbols from {fpath} with confidence {confidence}")
    sink_embed_mat = np.vstack(list(map(lambda x: x['embedding'], embeddings)))
    b_embeds = api.RE_embeddings(fpath).json()
    source_embed_mat = np.vstack(list(map(lambda x: x['embedding'], b_embeds)))
    # angular distance over cosine 
    # closest = 1.0 - distance.cdist(source_embed_mat, sink_embed_mat, 'cosine')
    closest = distance.cdist(source_embed_mat, sink_embed_mat, api.angular_distance)
    # rescale to separate high end of (-1, 1.0)
    # closest = rescale_sim(closest)
    i, j = closest.shape

    for _i in track(range(i), description='Matching Symbols...'):
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
                f"[bold green]Found match![/bold green][yellow]\tConfidence: {m_confidence:.05f}[/yellow]\t[blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t[blue]{sink_symb['name']}:{sink_symb['vaddr']}")
        elif (m_confidence - s_confidence) > deviation:
            rout.print(
                f"[bold magenta]Possible match[/bold magenta][yellow]\tConfidence: {m_confidence:.05f}/{s_confidence:.05f}[/yellow]\t[blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t[blue]{sink_symb['name']}:{sink_symb['vaddr']}")
        else:
            rerr.print(
                f"[bold red]No match for[/bold red]\t[blue]{source_symb['name']}:{source_symb['vaddr']}\t{sink_symb['name']} - {m_confidence:0.05f}[/blue]")
            pass


def match_for_each(fpath: str, model_name: str, confidence: float = 0.95, collections=None):
    """
    Match embeddings in fpath from a list of embeddings
    """
    if collections is None:
        collections = []
    print(f"Matching symbols from {fpath} with confidence {confidence}")
    b_embeds = api.RE_embeddings(fpath).json()
    b_hash = api.re_binary_id(fpath)

    with ThreadPoolExecutor(max_workers=cpu_count()) as p:
        # print(f"Collections: {collections}")
        partial = lambda x: api.RE_embeddings(fpath).json()
        res = {p.submit(partial, embed): embed for embed in b_embeds}

        for future in track(as_completed(res), description='Matching Symbols...'):
            # get result from future
            symbol = res[future]

            embedding = symbol['embedding']
            # do ANN call to match symbols, ignore functions from current file
            f_suggestions = api.RE_nearest_functions(fpath, nns=1, collections=collections,
                                                     ignore_hashes=[api.re_binary_id(fpath)]).json()

            if len(f_suggestions) == 0:
                # no match
                rerr.print(f"\t[bold red]No match for[/bold red]\t[blue]{symbol['name']}:{symbol['vaddr']}[/blue]")
                continue

            matched = f_suggestions[0]
            if matched['distance'] >= confidence:
                rout.print(
                    f"\t[bold green]Found match![/bold green][yellow]\tConfidence: {matched['distance']:.05f}[/yellow]\t[blue]{symbol['name']}:{symbol['vaddr']}[/blue]\t->\t[blue]{matched['name']}:{matched['sha_256_hash']}")
                continue

            rerr.print(f"\t[bold red]No match for[/bold red]\t[blue]{symbol['name']}:{symbol['vaddr']}[/blue]")


def parse_collections(collections: str):
    """
        Return collections as list from CSV
    """
    if not collections:
        return None
    return collections.split(',')


def rescale_sim(x):
    """
    Too many values close to 0.999, 0.99999, 0.998, rescale so small values are very low,
    high values separated, map to hyperbolic space
    """
    return np.power(x, 5)


def binary_similarity(fpath: str, fpaths: list, model_name: str):
    """
    Compute binary similarity between source and list of binary files
    """
    console = Console()

    table = Table(title=f"Binary Similarity to {fpath}")
    table.add_column("Binary", justify="right", style="cyan", no_wrap=True)
    table.add_column("SHA3-256", style="magenta", no_wrap=True)
    table.add_column("Similarity", style="yellow", no_wrap=True)

    b_embed = api.RE_signature(fpath).json()

    b_sums = []
    for b in track(fpaths, description='Computing Binary Similarity...'):
        try:
            b_sum = api.RE_signature(b).json()
            b_sums.append(b_sum)
        except Exception as e:
            rerr.print(f"\n[red bold]{b} Not Analysed[/red bold] - [green bold]{api.re_binary_id(b)}[/green bold]")
            rerr.print(e)

    if len(b_sums) > 0:
        # closest = 1.0 - distance.cdist(np.expand_dims(b_embed, axis=0), np.vstack(b_sums), 'cosine')
        closest = distance.cdist(np.expand_dims(b_embed, axis=0), np.vstack(b_sums), api.angular_distance)

        for binary, similarity in zip(fpaths, closest.tolist()[0]):
            # table.add_row(os.path.basename(binary), api.re_binary_id(binary), f"{rescale_sim(similarity):.05f}")
            table.add_row(os.path.basename(binary), api.re_binary_id(binary), f"{similarity:.05f}")

    rout.print(table)


def main() -> None:
    """
    Tool entry
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-b", "--binary", default="",
                        help="Path of binary to analyse, use ./path:{exec_format} to specify executable format e.g. ./path:raw-x86_64")
    parser.add_argument("-B", "--binary-hash", default="", help="Hex-encoded SHA-256 hash of the binary to use")
    parser.add_argument("-D", "--dir", default="", help="Path of directory to recursively analyse")
    parser.add_argument("-a", "--analyse", action='store_true',
                        help="Perform a full analysis and generate embeddings for every symbol")
    parser.add_argument("--no-embeddings", action='store_true',
                        help="Only perform binary analysis. Do not generate embeddings for symbols")
    parser.add_argument("--base-address", help="Image base of the executable image to map for remote analysis")
    parser.add_argument("-A", action='store_true', help="Upload and Analyse a new binary")
    parser.add_argument("-u", "--upload", action='store_true', help="Upload a new binary to remote server")
    parser.add_argument("--duplicate", default=False, action='store_true', help="Duplicate an existing binary")
    parser.add_argument("-n", "--ann", action='store_true',
                        help="Fetch Approximate Nearest Neighbours (ANNs) for embedding")
    parser.add_argument("-e", "--embedding", help="Path of JSON file containing a BinNet embedding")
    parser.add_argument("--nns", default="5", help="Number of approximate nearest neighbors to fetch")
    parser.add_argument("--collections", default=None,
                        help="Comma Seperated Value of collections to search from e.g. libxml2,libpcap. Used to select RevEng.AI collections for filtering search results")
    parser.add_argument("--found-in", help="ANN flag to limit to embeddings returned to those found in specific binary")
    parser.add_argument("--from-file",
                        help="ANN flag to limit to embeddings returned to those found in JSON embeddings file")
    parser.add_argument("-c", "--cves", action="store_true", help="Check for CVEs found inside binary")
    # parser.add_argument("-C", "--sca", action="store_true",
    #                     help="Perform Software Composition Anaysis to identify common libraries embedded in binary")
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM for binary")
    parser.add_argument("-m", "--model", default=None, help="AI model used to generate embeddings")
    parser.add_argument("-x", "--extract", action='store_true', help="Fetch embeddings for binary")
    parser.add_argument("--start-vaddr", help="Start virtual address of the function to extract embeddings")
    parser.add_argument("--symbol", help="Name of the symbol to extract embeddings")
    parser.add_argument("-s", "--signature", action='store_true', help="Generate a RevEng.AI binary signature")
    parser.add_argument("-S", "--similarity", action='store_true',
                        help="Compute similarity from a list of binaries. Option can be used with --from-file or -t flag with CSV of file paths. All binaries must be analysed prior to being used.")
    parser.add_argument("-t", "--to", help="CSV list of executables to compute binary similarity against")
    parser.add_argument("-M", "--match", action='store_true',
                        help="Match functions in binary file. Can be used with --confidence, --deviation, --from-file, --found-in.")
    parser.add_argument("--confidence", default="high", help="Confidence threshold used to match symbols.")
    parser.add_argument("--deviation", default=0.2,
                        help="Deviation in prediction confidence between outlier and next highest symbol. Use if confident symbol is present in binary but not matching.")
    parser.add_argument("-l", "--logs", action='store_true', help="Fetch analysis log file for binary")
    parser.add_argument("-d", "--delete", action='store_true', help="Delete all metadata associated with binary")
    parser.add_argument("-k", "--apikey", help="RevEng.AI API key")
    parser.add_argument("-h", "--host", help="Analysis Host (https://api.reveng.ai)")
    parser.add_argument("-v", "--version", action="store_true", help="Display version information")
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS,
                        help=argparse._('Show this help message and exit'))
    parser.add_argument("--isa", default=None, help="Override executable ISA. Valid values are x86, x86_64, ARMv7")
    parser.add_argument("--exec-format", default=None,
                        help="Override executable format. Valid values are pe, elf, macho, raw")
    parser.add_argument("--platform", default=None,
                        help="Override OS platform. Valid values are Windows, Linux, OSX, OpenBSD")
    parser.add_argument("--dynamic-execution", default=False, action='store_true',
                        help="Enable dynamic execution in sandbox during analysis. Analysis will include any auto unpacked malware samples")
    parser.add_argument("--cmd-line-args", default="",
                        help="Command line arguments to pass when running binary sample in the sandbox. Only used when run with --dynamic-execution")
    parser.add_argument("--scope", default="private", choices=["public", "private"],
                        help="Override analysis visibility (scope). Valid values are 'public' or 'private'[DEFAULT]")
    parser.add_argument("--tags", default=None, type=str,
                        help="Assign tags to an analysis. Valid responses are tag1,tag2,tag3..")
    parser.add_argument("--priority", default=0, type=int, help="Add priority to processing queue.")
    parser.add_argument("--verbose", default=False, action='store_true', help="Set verbose output.")
    args = parser.parse_args()

    # set re_conf args
    for arg in ('apikey', 'host', 'model'):
        if getattr(args, arg):
            api.re_conf[arg] = getattr(args, arg)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    # validate length of string tags
    if args.tags:
        # don't add non-content as tags
        if len(args.tags.strip()) == 0:
            args.tags = None

        else:
            # convert to list
            args.tags = args.tags.split(',')

    # display version and exit
    if args.version:
        version()
        exit(0)

    exec_fmt = None
    exec_isa = None
    base_address = 0
    if args.base_address:
        if args.base_address.upper()[:2] == "0X":
            base_address = int(args.base_address, 16)
        else:
            base_address = int(args.base_address)

    collections = None
    if args.collections:
        collections = parse_collections(args.collections)

    # auto analysis, uploads and starts analysis
    if args.A:
        args.upload = True
        args.analyse = True

    if args.dir:
        if not os.path.isdir(args.dir):
            rerr.print(f'Error, {args.dir} is not a valid directory path')
            exit(-1)

        files = iglob(os.path.abspath(args.dir) + '/**/*', recursive=True)
        ## perform operation on all files inside directory
        for file in track(files, description='Files in directory'):
            if not os.path.isfile(file):
                rerr.print(f'[blue]Skipping non-file[/blue] {file}')
                continue

            # upload binary
            if args.upload:
                api.RE_upload(file)

            if args.analyse:
                try:
                    fpath, exec_fmt, exec_isa = verify_binary(file)
                    rout.print(f'Found {fpath}:{exec_fmt}-{exec_isa}')
                    rout.print(f'[green bold]Analysing[/green bold] {file}')
                    api.RE_analyse(file, model_name=args.model, isa_options=args.isa, platform_options=args.platform,
                                   dynamic_execution=args.dynamic_execution, command_line_args=args.cmd_line_args,
                                   file_options=args.exec_format, binary_scope=args.scope.upper(), tags=args.tags,
                                   priority=args.priority, duplicate=args.duplicate, binary_size=getsize(fpath))
                except Exception as e:
                    rerr.print(f"[red bold][!] Error, binary exec type could not be verified[/red bold] {file}")

            if args.delete:
                try:
                    rout.print(f'[green bold]Deleting analyses for[/green bold] {file}')
                    api.RE_delete(file)
                except Exception as e:
                    rerr.print(f"[red bold][!] Error, could not delete analysis for [/red bold] {file}")
                    rerr.print(f"[yellow] {e} [/yellow]")
            if not (args.upload or args.analyse or args.delete):
                rerr.print(f'Error, -D only supports upload, analyse, or delete')
                exit(-1)

        exit(0)

    if args.A or args.analyse or args.extract or args.logs or args.delete or args.signature or args.similarity or args.upload or args.match or args.sbom:
        # verify binary is a file
        try:
            fpath, exec_fmt, exec_isa = verify_binary(args.binary)
            # keep stdout to data only
            rerr.print(f'Found {fpath}:{exec_fmt}-{exec_isa}')
            args.binary = fpath
        except Exception as e:
            rerr.print(f"[bold red]{str(e)}[/bold red]")
            rerr.print("[bold red][!] Error, please supply a valid binary file using '-b'.[/bold red]")
            # parser.print_help()
            exit(-1)

    if args.upload:

        api.RE_upload(args.binary)

        if not args.analyse:
            exit(0)
        # upload binary first, them carry out actions

    if args.analyse:
        api.RE_analyse(args.binary, model_name=args.model, isa_options=args.isa, platform_options=args.platform,
                       dynamic_execution=args.dynamic_execution, command_line_args=args.cmd_line_args,
                       file_options=args.exec_format, binary_scope=args.scope.upper(), tags=args.tags,
                       priority=args.priority, duplicate=args.duplicate, binary_size=getsize(args.binary))

    elif args.extract:
        embeddings = api.RE_embeddings(args.binary).json()
        print_json(data=embeddings)

    elif args.signature and not args.ann:
        # Arithetic mean of symbol embeddings
        b_embed = api.RE_signature(args.binary).json()
        print_json(data=b_embed)

    elif args.similarity:
        # compute binary similarity from list of executables
        if args.from_file:
            binaries = list(map(lambda x: x.strip(), open(args.from_file, 'r').readlines()))
        else:
            if not args.to:
                print(f"Error, please specify --from-file or --to to compute binary similarity against")
                exit(-1)
            binaries = args.to.split(",")

        # verify all binaries are valid files
        for b in binaries:
            verify_binary(b)

        binary_similarity(args.binary, binaries, args.model)

    elif args.ann:
        # parse embedding json file
        if args.embedding:
            if not isfile(args.embedding):
                print("[!] Error, please supply a valid embedding JSON file using '-e'")
                parser.print_help()
                exit(-1)

            embedding = json.loads(open(args.embedding, 'r').read())
        elif (args.symbol or args.start_vaddr) and args.binary:
            if args.start_vaddr:
                if args.start_vaddr.upper()[:2] == "0X":
                    vaddr = int(args.start_vaddr, 16) + base_address
                else:
                    vaddr = int(args.start_vaddr) + base_address

                print(
                    f"[+] Using symbol starting at vaddr {hex(vaddr)} from {args.binary} (image_base:{hex(base_address)})")
                embeddings = api.RE_embeddings(args.binary).json()
                matches = list(filter(lambda x: x['vaddr'] == vaddr, embeddings))
                if len(matches) == 0:
                    print(f"[!] Error, could not find symbol at {hex(vaddr)} in {args.binary}")
                    exit(-1)
                embedding = matches[0]['embedding']
            else:
                print(f"[+] Using symbol {args.symbol} from {args.binary}")

                embeddings = api.RE_embeddings(args.binary).json()
                matches = list(filter(lambda x: x['name'] == args.symbol, embeddings))
                if len(matches) == 0:
                    print(f"[!] Error, could not find symbol at {args.symbol} in {args.binary}")
                    exit(-1)
                embedding = matches[0]['embedding']
        elif args.binary:
            print(f"[+] Searching ANN for binary embeddings {args.binary}")
            b_suggestions = api.RE_nearest_functions(args.binary, nns=args.nns,
                                                     collections=collections,
                                                     ignore_hashes=[api.re_binary_id(args.binary)]).json()
            print_json(data=b_suggestions)
            exit(0)
        else:
            rerr.print("[bold red][!] Error, please supply a valid embedding JSON file using '-e', or select a function"
                       " using --start-vaddr or --symbol (NB: -b flag is needed for both of these options).[/bold red]")
            # parser.print_help()
            exit(-1)

        if args.found_in:
            if not os.path.isfile(args.found_in):
                print("[!] Error, --found-in flag requires a path to a binary to search from")
                exit(-1)
            print(f"[+] Searching for symbols similar to embedding in binary {args.found_in}")
            embeddings = api.RE_embeddings(args.found_in).json()
            res = api.RE_compute_distance(embedding, embeddings, int(args.nns))
            print_json(data=res)
        elif args.from_file:
            if not os.path.isfile(args.from_file):
                print("[!] Error, --from-file flag requires a path to a JSON embeddings file")
                exit(-1)
            print(f"[+] Searching for symbols similar to embedding in binary {args.from_file}")
            res = api.RE_compute_distance(embedding, json.load(open(args.from_file, "r")), int(args.nns))
            print_json(data=res)

    elif args.match:
        # parse confidences
        confidence = 0.90
        if args.confidence:
            confidences = {
                'high': 0.95,
                'medium': 0.9,
                'low': 0.7,
                'partial': 0.5,
                'all': 0.0
            }
            if args.confidence in confidences.keys():
                confidence = confidences[args.confidence]
            else:
                confidence = float(args.confidence)

        if args.from_file:
            embeddings = json.load(open(args.from_file, 'r'))
        elif args.found_in:
            if not os.path.isfile(args.found_in):
                print("[!] Error, --found-in flag requires a path to a binary to search from")
                exit(-1)
            print(f"[+] Matching symbols between {args.binary} and {args.found_in}")
            embeddings = api.RE_embeddings(args.found_in).json()
        else:
            # print("No --from-file or --found-in, matching from global symbol database (unstrip) not currently")
            match_for_each(args.binary, args.model, confidence, collections)
            exit(-1)

        match(args.binary, args.model, embeddings, confidence=confidence, deviation=float(args.deviation))

    # elif args.sca:
    #     api.RE_sca(args.binary)

    elif args.logs:
        api.RE_logs(args.binary)

    elif args.delete:
        api.RE_delete(args.binary)

    elif args.sbom:
        api.RE_SBOM(args.binary)

    elif args.cves:
        api.RE_cves(args.binary)
    else:
        print("[!] Error, please supply an action command")
        parser.print_help()


if __name__ == '__main__':
    main()

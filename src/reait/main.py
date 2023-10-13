#!/usr/bin/env python
from __future__ import print_function
from hashlib import sha256
from rich import print_json, print as rich_print
from rich.progress import track
from rich.console import Console
from rich.table import Table
import os
import re
import argparse
import requests
from numpy import array, vstack, mean, average
from pandas import DataFrame
import json
import tomli
from os.path import isfile
from sys import exit
from IPython import embed
from reait import api
from scipy.spatial import distance
from scipy.special import expit
from glob import iglob
import numpy as np

def version():
    """
        Display program version
    """
    rich_print(f"[bold red]reait[/bold red] [bold bright_green]v{api.__version__}[/bold bright_green]")
    print_json(data=api.re_conf)


def verify_binary(fpath_fmt: str):
    fmt     = None
    fpath   = fpath_fmt

    if ':' in fpath_fmt:
        fpath, fmt = fpath_fmt.split(':')

    if not os.path.isfile(fpath):
        raise RuntimeError(f"File path {fpath} is not a file")

    if not fmt:
        exec_format, exec_isa = api.file_type(fpath)
    else:
        if '-' not in fmt:
            raise RuntimeError('Binary type must follow format {EXEC_FORMAT}-{ISA}. Use EXEC_FORMAT raw for memory dumps e.g. raw-x86')

        exec_format, exec_isa = fmt.split('-')

    return fpath, exec_format, exec_isa


def match(fpath: str, model_name: str, embeddings: list, confidence: float = 0.95, deviation: float = 0.1):
    """
    Match embeddings in fpath from a list of embeddings
    """
    print(f"Matching symbols from {fpath} with confidence {confidence}")
    sink_embed_mat = np.vstack(list(map(lambda x: x['embedding'], embeddings)))
    b_embeds = api.RE_embeddings(fpath, model_name)
    source_embed_mat = np.vstack(list(map(lambda x: x['embedding'], b_embeds)))
    # angular distance over cosine 
    #closest = 1.0 - distance.cdist(source_embed_mat, sink_embed_mat, 'cosine')
    closest = distance.cdist(source_embed_mat, sink_embed_mat, api.angular_distance)
    # rescale to separate high end of (-1, 1.0)
    closest = rescale_sim(closest)
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
            rich_print(f"[bold green]Found match![/bold green][yellow]\tConfidence: {m_confidence:.05f}[/yellow]\t[blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t[blue]{sink_symb['name']}:{sink_symb['vaddr']}")
        elif (m_confidence - s_confidence) > deviation:
            rich_print(f"[bold magenta]Possible match[/bold magenta][yellow]\tConfidence: {m_confidence:.05f}/{s_confidence:.05f}[/yellow]\t[blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t[blue]{sink_symb['name']}:{sink_symb['vaddr']}")
        else:
            #rich_print(f"[bold red]No match for[/bold red]\t[blue]{source_symb['name']}:{source_symb['vaddr']}\t{sink_symb['name']} - {m_confidence:0.05f}[/blue]")
            pass

        
def rescale_sim(x):
    """
        Too many values close to 0.999, 0.99999, 0.998, rescale so small values are very low, high values seperated, map to hyperbolic space
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

    b_embed = api.RE_signature(fpath, model_name)

    b_sums = []
    for b in track(fpaths, description='Computing Binary Similarity...'):
        try:
            b_sum = api.RE_signature(b, model_name)
            b_sums.append(b_sum)
        except Exception as e:
            console.print(f"\n[red bold]{b} Not Analysed[/red bold] - [green bold]{api.binary_id(b)}[/green bold]")
            console.print(e)

    if len(b_sums) > 0:
            #closest = 1.0 - distance.cdist(np.expand_dims(b_embed, axis=0), np.vstack(b_sums), 'cosine')
            closest = distance.cdist(np.expand_dims(b_embed, axis=0), np.vstack(b_sums), api.angular_distance)

            for binary, similarity in zip(fpaths, closest.tolist()[0]):
                table.add_row(os.path.basename(binary), api.binary_id(binary), f"{rescale_sim(similarity):.05f}")

    console.print(table)


def main() -> None:
    """
    Tool entry
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-b", "--binary", default="", help="Path of binary to analyse, use ./path:{exec_format} to specify executable format e.g. ./path:raw-x86_64")
    parser.add_argument("-D", "--dir", default="", help="Path of directory to recursively analyse")
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
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM for binary")
    parser.add_argument("-m", "--model", default="binnet-0.1", help="AI model used to generate embeddings")
    parser.add_argument("-x", "--extract", action='store_true', help="Fetch embeddings for binary")
    parser.add_argument("--start-vaddr", help="Start virtual address of the function to extract embeddings")
    parser.add_argument("--symbol", help="Name of the symbol to extract embeddings")
    parser.add_argument("-s", "--signature", action='store_true', help="Generate a RevEng.AI binary signature")
    parser.add_argument("-S", "--similarity", action='store_true', help="Compute similarity from a list of binaries. Option can be used with --from-file or -t flag with CSV of file paths. All binaries must be analysed prior to being used.")
    parser.add_argument("-t", "--to", help="CSV list of executables to compute binary similarity against")
    parser.add_argument("-M", "--match", action='store_true', help="Match functions in binary file. Can be used with --confidence, --deviation, --from-file, --found-in.")
    parser.add_argument("--confidence", default="high", help="Confidence threshold used to match symbols.")
    parser.add_argument("--deviation", default=0.2, help="Deviation in prediction confidence between outlier and next highest symbol. Use if confident symbol is present in binary but not matching.")
    parser.add_argument("-l", "--logs", action='store_true', help="Fetch analysis log file for binary")
    parser.add_argument("-d", "--delete", action='store_true', help="Delete all metadata associated with binary")
    parser.add_argument("-k", "--apikey", help="RevEng.AI API key")
    parser.add_argument("-h", "--host", help="Analysis Host (https://api.reveng.ai)")
    parser.add_argument("-v", "--version", action="store_true", help="Display version information")
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help=argparse._('Show this help message and exit'))
    parser.add_argument("--isa", default=None, help="Override executable ISA. Valid values are x86, x86_64, ARMv7")
    parser.add_argument("--exec-format", default=None, help="Override executable format. Valid values are pe, elf, macho, raw")
    parser.add_argument("--platform", default=None, help="Override OS platform. Valid values are Windows, Linux, OSX, OpenBSD")
    parser.add_argument("--dynamic-execution", default=False, action='store_true', help="Enable dynamic execution in sandbox during analysis. Analysis will include any auto unpacked malware samples")
    parser.add_argument("--cmd-line-args", default="", help="Command line arguments to pass when running binary sample in the sandbox. Only used when run with --dynamic-execution")
    parser.add_argument("--scope", default="private", help="Override analysis visibility (scope). Valid values are 'public' or 'private'[DEFAULT]")
    parser.add_argument("--tags", default=None, help="Assign tags to an analysis. Valid responses are tag1,tag2,tag3..")
    args = parser.parse_args()

    if args.apikey:
        api.re_conf['apikey'] = args.apikey
    if args.host:
        api.re_conf['host'] = args.host
    if args.model:
        api.re_conf['model'] = args.model

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


    if args.dir:
        if not os.path.isdir(args.dir):
            rich_print(f'Error, {args.dir} is not a valid directory path')
            exit(-1)

        files = iglob(os.path.abspath(args.dir) + '/**/*', recursive=True)
        ## perform operation on all files inside directory
        for file in track(files, description='Files in directory'):
            if not os.path.isfile(file):
                #rich_print(f'[blue]Skipping non-file[/blue] {file}')
                continue

            if args.analyse:
                try:
                    fpath, exec_fmt, exec_isa = verify_binary(file)
                    rich_print(f'Found {fpath}:{exec_fmt}-{exec_isa}')
                    rich_print(f'[green bold]Analysing[/green bold] {file}')
                    api.RE_analyse(file, model=args.model, isa_options=args.isa, platform_options=args.platform, dynamic_execution=args.dynamic_execution, command_line_args=args.cmd_line_args, file_options=args.exec_format, scope=args.scope.upper(), tags=args.tags)
                except Exception as e:
                    rich_print(f"[red bold][!] Error, binary exec type could not be verified[/red bold] {file}")

            elif args.delete:
                try:
                    rich_print(f'[green bold]Deleting analyses for[/green bold] {file}')
                    api.RE_delete(args.binary, args.model)
                except Exception as e:
                    rich_print(f"[red bold][!] Error, could not delete analysis for [/red bold] {file}")
            else:
                rich_print(f'Error, -D only supports analyse or delete')
                exit(-1)

        exit(0)

    if args.A or args.analyse or args.extract or args.logs or args.delete or args.signature or args.similarity or args.upload or args.match or args.sbom:
        # verify binary is a file
        try:
            fpath, exec_fmt, exec_isa = verify_binary(args.binary)
            rich_print(f'Found {fpath}:{exec_fmt}-{exec_isa}')
            args.binary = fpath
        except Exception as e:
            print("[!] Error, please supply a valid binary file using '-b'.")
            parser.print_help()
            exit(-1)

    if args.upload:
        # upload binary first, them carry out actions
        print(f"[!] RE:upload not implemented. Use analyse.")
        exit(-1)

    if args.analyse:
        api.RE_analyse(args.binary, model=args.model, isa_options=args.isa, platform_options=args.platform, dynamic_execution=args.dynamic_execution, command_line_args=args.cmd_line_args, file_options=args.exec_format, scope=args.scope.upper(), tags=args.tags)

    elif args.extract:
        embeddings = api.RE_embeddings(args.binary, args.model)
        print_json(data=embeddings)

    elif args.signature and not args.ann:
        # Arithetic mean of symbol embeddings
        b_embed = api.RE_signature(args.binary, args.model)
        print_json(data=b_embed)

    elif args.similarity:
        #compute binary similarity from list of executables
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
        source = None
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

                print(f"[+] Using symbol starting at vaddr {hex(vaddr)} from {args.binary} (image_base:{hex(base_address)})")
                embeddings = api.RE_embeddings(args.binary, args.model)
                matches = list(filter(lambda x: x['vaddr'] == vaddr, embeddings))
                if len(matches) == 0:
                    print(f"[!] Error, could not find symbol at {hex(vaddr)} in {args.binary}")
                    exit(-1)
                embedding = matches[0]['embedding']
            else:
                symb_name = args.symbol
                print(f"[+] Using symbol {args.symbol} from {args.binary}")

                embeddings = api.RE_embeddings(args.binary, args.model)
                matches = list(filter(lambda x: x['name'] == args.symbol, embeddings))
                if len(matches) == 0:
                    print(f"[!] Error, could not find symbol at {args.symbol} in {args.binary}")
                    exit(-1)
                embedding = matches[0]['embedding']
        elif args.binary and args.signature:
            print(f"[+] Searching ANN for binary embeddings {args.binary}")
            api.RE_nearest_binaries(api.RE_signature(args.binary, args.model), args.model, args.nns, args.collections)
            exit(0)
        else:
            print("[!] Error, please supply a valid embedding JSON file using '-e', or select a function using --start-vaddr or --symbol (NB: -b flag is needed for both of these options).")
            parser.print_help()
            exit(-1)


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
            embeddings = api.RE_embeddings(args.found_in, args.model)
            res = api.RE_compute_distance(embedding, embeddings, int(args.nns))
            print_json(data=res)
        elif args.from_file:
            if not os.path.isfile(args.from_file):
                print("[!] Error, --from-file flag requires a path to a JSON embeddings file")
                exit(-1)
            print(f"[+] Searching for symbols similar to embedding in binary {args.from_file}")
            res = api.RE_compute_distance(embedding, json.load(open(args.from_file, "r")), int(args.nns))
            print_json(data=res)
        else:
            print(f"[+] Searching for similar symbols to embedding in {'all' if not args.collections else args.collections} collections.")
            api.RE_nearest_symbols(embedding, args.model, int(args.nns), collections=args.collections)


    elif args.match:
        embeddings = None
        if args.from_file:
            embeddings = json.load(open(args.from_file, 'r'))
        elif args.found_in:
            if not os.path.isfile(args.found_in):
                print("[!] Error, --found-in flag requires a path to a binary to search from")
                exit(-1)
            print(f"[+] Matching symbols between {args.binary} and {args.found_in}")
            embeddings = api.RE_embeddings(args.found_in, args.model)
        else:
            print("No --from-file or --found-in, matching from global symbol database (unstrip) not currently")
            exit(-1)

        confidence = 0.99
        if args.confidence:
            confidences = {
                'high': 0.99,
                'medium': 0.95,
                'low': 0.9,
                'all': 0.0
            }
            if args.confidence in confidences.keys():
                confidence = confidences[args.confidence]
            else:
                confidence = float(args.confidence)
            
        match(args.binary, args.model, embeddings, confidence=confidence, deviation=float(args.deviation))


    elif args.sca:
        api.RE_sca(args.binary)

    elif args.logs:
        api.RE_logs(args.binary, args.model)

    elif args.delete:
        api.RE_delete(args.binary, args.model)

    elif args.sbom:
        api.RE_SBOM(args.binary, args.model)

    elif args.cves:
        api.RE_cves(args.binary, args.model)
    else:
        print("[!] Error, please supply an action command")
        parser.print_help()


if __name__ == '__main__':
    main()

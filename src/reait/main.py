#!/usr/bin/env python
from __future__ import print_function
from hashlib import sha256
from rich import print_json, print as rich_print
from rich.progress import track
from rich.console import Console
from rich.table import Table
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
from reait import api
from scipy.spatial import distance
import numpy as np

def version():
	"""
		Display program version
	"""
	rich_print(f"[bold red]reait[/bold red] [bold bright_green]v{api.__version__}[/bold bright_green]")
	print_json(data=api.re_conf)


def match(fpath: str, embeddings: list, confidence: float = 0.95):
	"""
	Match embeddings in fpath from a list of embeddings
	"""
	print(f"Matching symbols from {fpath} with confidence {confidence}")
	sink_embed_mat = np.vstack(map(lambda x: x['embedding'], embeddings))
	b_embeds = api.RE_embeddings(fpath)
	source_embed_mat = np.vstack(map(lambda x: x['embedding'], b_embeds))
	closest = cosine_similarity(source_embed_mat, sink_embed_mat)
	i, j = closest.shape

	for _i in track(range(i), description='Matching Symbols...'):
		row = closest[_i, :]
		match_index = row.argsort()[::-1][0]
		if row[match_index] >= confidence:
			source_index = _i
			sink_index = match_index

			source_symb = b_embeds[_i]
			sink_symb = embeddings[sink_index]

			m_confidence = row[match_index]

			rich_print(f"[bold green]Found match! with {m_confidence:.03} confidence[/bold green] [blue]{source_symb['name']}:{source_symb['vaddr']}[/blue]\t->\t[blue]{sink_symb['name']}:{sink_symb['vaddr']}")
		

def binary_similarity(fpath: str, fpaths: list):
	"""
	Compute binary similarity between source and list of binary files
	"""
	console = Console()
	embeddings = api.RE_embeddings(fpath)
	b_embed = mean(vstack(list(map(lambda x: array(x['embedding']), embeddings))), axis=0)

	b_sums = []
	for b in track(fpaths, description='Computing Binary Similarity...'):
		try:
			b_embeddings = api.RE_embeddings(b)
			b_sum = mean(vstack(list(map(lambda x: array(x['embedding']), embeddings))), axis=0)
			b_sums.append(b_sum)
		except Exception as e:
			print(e)
			b_sums.append("Not Analysed")

	closest = cosine_similarity(b_embed, b_sums)

	table = Table(title="Binary Similarity to {fpath}")
	table.add_column("Binary", justify="right", style="cyan", no_wrap=True)
	table.add_column("Similarity", style="cyan", no_wrap=True)
	table.add_column("SHA3-256", style="yellow", no_wrap=True)

	for binary, similarity in zip(*fpaths, closest):
		table.add_row(os.path.basename(binary), similarity, api.binary_id(binary))


def main() -> None:
	"""
	Tool entry
	"""
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
	parser.add_argument("-sbom", action="store_true", help="Generate SBOM for binary")
	parser.add_argument("-m", "--model", default="binnet-0.1", help="AI model used to generate embeddings")
	parser.add_argument("-x", "--extract", action='store_true', help="Fetch embeddings for binary")
	parser.add_argument("--start-address", help="Start vaddr of the function to extract embeddings")
	parser.add_argument("--end-address", help="End vaddr of the function to extract embeddings")
	parser.add_argument("-s", "--signature", action='store_true', help="Generate a RevEng.AI binary signature")
	parser.add_argument("-S", "--similarity", action='store_true', help="Compute similarity from a list of binaries. Option can be used with --from-file or -t flag with csv file paths. All binaries must be analysed prior to being used.")
	parser.add_argument("-t", "--to", help="CSV list of executables to compute binary similarity against")
	parser.add_argument("-M", "--match", action='store_true', help="Match functions in binary file. Can be used with --confidence, --from-file.")
	parser.add_argument("--confidence", default=None, help="Confidence threshold used to match symbols.")
	parser.add_argument("-l", "--logs", action='store_true', help="Fetch analysis log file for binary")
	parser.add_argument("-d", "--delete", action='store_true', help="Delete all metadata associated with binary")
	parser.add_argument("-k", "--apikey", help="RevEng.AI API key")
	parser.add_argument("-h", "--host", help="Analysis Host (https://api.reveng.ai)")
	parser.add_argument("-v", "--version", action="store_true", help="Display version information")
	parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help=argparse._('Show this help message and exit'))
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

	if args.A or args.analyse or args.extract or args.logs or args.delete or args.signature or args.similarity or args.upload or args.match:
		# verify binary is a file
		if not os.path.isfile(args.binary):
			print("[!] Error, please supply a valid binary file using '-b'.")
			parser.print_help()
			exit(-1)

	if args.upload:
		# upload binary first, them carry out actions
		print(f"[!] RE:upload not implemented. Use analyse.")
		exit(-1)

	if args.analyse:
		api.RE_analyse(args.binary)

	elif args.extract:
		embeddings = api.RE_embeddings(args.binary)
		print_json(data=embeddings)

	elif args.signature:
		# Arithetic mean of symbol embeddings
		embeddings = api.RE_embeddings(args.binary)
		b_embed = mean(vstack(list(map(lambda x: array(x['embedding']), embeddings))), axis=0)
		print_json(data=b_embed.tolist())

	elif args.similarity:
		#compute binary similarity from list of executables
		if args.from_file:
			binaries = open(args.from_file, 'r').readlines()
		else:
			if not args.to:
				printf(f"Error, please specify --from-file or --to to compute binary similarity against")
				exit(-1)
			binaries = [args.to]
		binary_similarity(args.binary, binaries)

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
			embeddings = api.RE_embeddings(args.found_in)
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
			api.RE_nearest_symbols(embedding, int(args.nns), collections=args.collections)


	elif args.match:
		if args.from_file:
			embeddings = json.load(open(args.from_file, 'r'))
		else:
			print("No --from-file, matching from global symbol database (unstrip) not currently")
			exit(-1)

		confidence = 0.95
		if args.confidence:
			confidences = {
				'high': 0.95,
				'medium': 0.9,
				'low': 0.8,
				'all': 0.0
			}
			if args.confidence in confidences.keys():
				confidence = confidences[args.confidence]
			else:
				confidence = float(args.confidence)
			
		match(args.binary, embeddings, confidence=confidence)

	elif args.logs:
		api.RE_logs(args.binary)

	elif args.delete:
		api.RE_delete(args.binary)

	elif args.cves:
		api.RE_cves(args.binary)
	else:
		print("[!] Error, please supply an action command")
		parser.print_help()


if __name__ == '__main__':
	main()

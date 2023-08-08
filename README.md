# reait

## <ins>R</ins>ev<ins>E</ins>ng.<ins>AI</ins> <ins>T</ins>oolkit

Analyse compiled executable binaries using the RevEng.AI API. This tool allows you to search for similar components across different compiled executable programs, identify known vulnerabilities in stripped executables, and generate "YARA++" **REAI** signatures for entire binary files. More details about the API can be found at [docs.reveng.ai](https://docs.reveng.ai).

NB: We are in Alpha. We support GNU/Linux ELF and Windows PE executables for x86_64, and focus our support for x86_64 Linux ELF executables. 

## Installation

Install the latest stable version using pip.

`pip install reait`

### Latest development version

`pip install -e .`

or 

```
python3 -m build .
pip install -U dist/reait-*.whl
```

## Using reait

### Analysing binaries
To submit a binary for analysis, run `reait` with the `-a` flag:

`reait -b /usr/bin/true -a`

This uploads the binary specified by `-b` to RevEng.AI servers for analysis. Depending on the size of the binary, it may take several hours. You may check an analysis jobs progress with the `-l` flag e.g. `reait -b /usr/bin/true -l`.

### Extract symbol embeddings
Symbol embeddings are numerical vector representations of each component that capture their semantic understanding. Similar functions should be similar to each other in our embedded vector space. They can be thought of as *advanced* AI-based IDA FLIRT signatures or Radare2 Zignatures.
Once an analysis is complete, you may access RevEng.AI's BinNet embeddings for all symbols extracted with the `-x` flag. 

`reait -b /usr/bin/true -x > embeddings.json`

#### Extract embedding for symbol at vaddr 0x19f0
`reait -b /usr/bin/true -x | jq ".[] | select(.vaddr==$((0x19f0))).embedding" > embedding.json`


### Search for similar symbols using an embedding
To query our database of similar symbols based on an embedding, use `-n` to search using Approximate Nearest Neighbours. The `--nns` allows you to specify the number of results returned. A list of symbols with their names, distance (similarity), RevEng.AI collection set, source code filename, source code line number, and file creation timestamp is returned. 

`reait -e embedding.json -n`

The following command searches for the top 10 most similar symbols found in md5sum.gcc.og.dynamic to the symbol starting at 0x4037e0 in md5sum.clang.og.dynamic. You may need to pass `--image-base` to ensure virtual addresses are mapped correctly.

`reait -b md5sum.gcc.og.dynamic -n --start-vaddr 0x33e6 --found-in md5sum.gcc.o2.dynamic --nns 10 --base-address 0x100000`

Search NN by symbol name.
`reait -b md5sum.gcc.og.dynamic -n --symbol md5_buffer --found-in md5sum.gcc.o2.dynamic --nns 5`

NB: A smaller distance indicates a higher degree of similarity.

#### Specific Search
To search for the most similar symbols found in a specific binary, use the `--found-in` option with a path to the executable to search from.

`reait -n --embedding /tmp/sha256_init.json --found-in ~/malware.exe --nns 5` 

This downloads embeddings from `malware.exe` and computes the cosine similarity between all symbols and `sha256_init.json`. The returned results lists the most similar symbol locations by cosine similarity score (1.0 most similar, -1.0 dissimilar).

The `--from-file` option may also be used to limit the search to a custom file containing a JSON list of embeddings.


#### Limited Search
To search for most similar symbols from a set of RevEng.AI collections, use the `--collections` options with a RegEx to match collection names. For example:

`reait -n --embedding my_func.json --collections "(libc.*|lib.*crypt.*)"`

RevEng.AI collections are sets of pre-analysed executable objects. To create custom collection sets e.g., malware collections, please create a RevEng.AI account.


### Unstripping binaries

Find common components between binaries, RevEng.AI collections, or global search, by using `-M, --match`.

Example usage: 

```
reait -M -b 05ff897f430fec0ac17f14c89181c76961993506e5875f2987e9ead13bec58c2.exe --from-file 755a4b2ec15da6bb01248b2dfbad206c340ba937eae9c35f04f6cedfe5e99d63.embeddings.json --confidence high
```

### RevEng.AI embedding models
To use specific RevEng.AI AI models, or for training custom models, use `-m` to specify the model. The default option is to use the latest development model. Available models are `binnet-0.1` and `dexter`.

`reait -b /usr/bin/true -m dexter -a`

### Software Composition Analysis
To identify known open source software components embedded inside a binary, use the `-C` flag.

#### Stripped Binary CVE Checker
To check for known vulnerabilities found with embedded software components, use `-c` or `--cves`.


### REAI Signatures
To generate an AI functional description of an entire binary file, use the `-s` flag. This will return the REAI signature of the file.

REAI signatures can be used to compute the binary similarity between entire executables with the `-S` flag. For example:

```
reait -b d24ccf73aabca4192d33a07b4a238c8d40ac97a550c2e65b8074f03455a981ca.exe -S -t 00062cb01088cea245cd5f3eb03f65a0e6b11a8126ce00034d87935a451cf99c.exe,438d64bb831555caadaa92a32c9d62e255001bc8d524721c885f37d750ec3476.exe,755a4b2ec15da6bb01248b2dfbad206c340ba937eae9c35f04f6cedfe5e99d63.exe,05ff897f430fec0ac17f14c89181c76961993506e5875f2987e9ead13bec58c2.exe
Computing Binary Similarity... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:01
                      Binary Similarity to RedlineInfoStealer/d24ccf73aabca4192d33a07b4a238c8d40ac97a550c2e65b8074f03455a981ca.exe                      
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃                                                               Binary ┃ SHA3-256                                                         ┃ Similarity ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 00062cb01088cea245cd5f3eb03f65a0e6b11a8126ce00034d87935a451cf99c.exe │ 00062cb01088cea245cd5f3eb03f65a0e6b11a8126ce00034d87935a451cf99c │ 0.99907    │
│ 438d64bb831555caadaa92a32c9d62e255001bc8d524721c885f37d750ec3476.exe │ 438d64bb831555caadaa92a32c9d62e255001bc8d524721c885f37d750ec3476 │ 1.00000    │
│ 755a4b2ec15da6bb01248b2dfbad206c340ba937eae9c35f04f6cedfe5e99d63.exe │ 755a4b2ec15da6bb01248b2dfbad206c340ba937eae9c35f04f6cedfe5e99d63 │ 0.80522    │
│ 05ff897f430fec0ac17f14c89181c76961993506e5875f2987e9ead13bec58c2.exe │ 05ff897f430fec0ac17f14c89181c76961993506e5875f2987e9ead13bec58c2 │ 0.94701    │
└──────────────────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────┴────────────┘
```

## Configuration

`reait` reads the config file stored at `~/.reait.toml`. An example config file looks like:

```
apikey = "l1br3"
host = "https://api.reveng.ai"
model = "binnet-0.1"
```

## Contact
Connect with us by filling out the contact form at [RevEng.AI](https://reveng.ai).

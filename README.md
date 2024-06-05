# reait

[![Python package](https://github.com/RevEngAI/reait/actions/workflows/python-package.yml/badge.svg)](https://github.com/RevEngAI/reait/actions/workflows/python-package.yml)

## <ins>R</ins>ev<ins>E</ins>ng.<ins>AI</ins> <ins>T</ins>oolkit

Analyse compiled executable binaries using the RevEng.AI API. This tool allows you to search for similar components across different compiled executable programs, identify known vulnerabilities in stripped executables, and generate "YARA++" **REAI** signatures for entire binary files. More details about the API can be found at [docs.reveng.ai](https://docs.reveng.ai).

NB: We are in Alpha. We support GNU/Linux ELF and Windows PE executables for x86_64, and focus our support for x86_64 Linux ELF executables. 

## Installation
Install the latest stable version using `pip3`.

```shell
pip3 install reait
```

### Latest development version
```shell
pip3 install -e .
```

or 

```shell
python3 -m build .
pip3 install -U dist/reait-*.whl
```

## Using reait

### Analysing binaries
To submit a binary for analysis, run `reait` with the `-a` flag:

```shell
reait -b /usr/bin/true -a
```

This uploads the binary specified by `-b` to RevEng.AI servers for analysis. Depending on the size of the binary, it may take several hours. You may check an analysis jobs progress with the `-l` flag e.g. `reait -b /usr/bin/true -l`.

### Extract symbol embeddings
Symbol embeddings are numerical vector representations of each component that capture their semantic understanding. Similar functions should be similar to each other in our embedded vector space. They can be thought of as *advanced* AI-based IDA FLIRT signatures or Radare2 Zignatures.
Once an analysis is complete, you may access RevEng.AI's BinNet embeddings for all symbols extracted with the `-x` flag. 

```shell
reait -b /usr/bin/true -x > embeddings.json
```

### Search for similar symbols using an embedding
To query our database of similar symbols based on an embedding, use `-n` to search using Approximate Nearest Neighbours. The `--nns` allows you to specify the number of results returned. A list of symbols with their names, distance (similarity), RevEng.AI collection set, source code filename, source code line number, and file creation timestamp is returned. 

```shell
reait --embedding embedding.json -n
```

The following command searches for the top 10 most similar symbols found in md5sum.gcc.og.dynamic to the symbol starting at _0x33E6_ in md5sum.clang.og.dynamic. You may need to pass `--image-base` to ensure virtual addresses are mapped correctly.

```shell
reait -b md5sum.gcc.og.dynamic -n --start-vaddr 0x33E6 --found-in md5sum.gcc.o2.dynamic --nns 10 --base-address 0x100000
```

Search NN by symbol name.
```shell
reait -b md5sum.gcc.og.dynamic -n --symbol md5_buffer --found-in md5sum.gcc.o2.dynamic --nns 5
```

NB: A smaller distance indicates a higher degree of similarity.

#### Specific Search
To search for the most similar symbols found in a specific binary, use the `--found-in` option with a path to the executable to search from.

```shell
reait -n --embedding /tmp/sha256_init.json --found-in ~/malware.exe --nns 5
``` 

This downloads embeddings from `malware.exe` and computes the cosine similarity between all symbols and `sha256_init.json`. The returned results lists the most similar symbol locations by cosine similarity score (1.0 most similar, -1.0 dissimilar).

The `--from-file` option may also be used to limit the search to a custom file containing a JSON list of embeddings.


#### Limited Search
To search for most similar symbols from a set of RevEng.AI collections, use the `--collections` options with a RegEx to match collection names. For example:

```shell
reait -n --embedding my_func.json --collections "(libc.*|lib.*crypt.*)"
```

RevEng.AI collections are sets of pre-analysed executable objects. To create custom collection sets e.g., malware collections, please create a RevEng.AI account.


### Unstripping binaries

Find common components between binaries, RevEng.AI collections, or global search, by using `-M, --match`.

Example usage: 

```shell
reait -M -b 05ff897f430fec0ac17f14c89181c76961993506e5875f2987e9ead13bec58c2.exe --from-file 755a4b2ec15da6bb01248b2dfbad206c340ba937eae9c35f04f6cedfe5e99d63.embeddings.json --confidence high
```

### RevEng.AI embedding models
To use specific RevEng.AI AI models, or for training custom models, use `-m` to specify the model. The default option is to use the latest development model. Available models are `binnet-0.1` and `dexter`.

```shell
reait -b /usr/bin/true -m dexter -a
```

### Software Composition Analysis
To identify known open source software components embedded inside a binary, use the `-C` flag.


### Binary ANN Search
To perform binary ANN search, pass in `-n` and `-s` flag at the same time. For example:

```shell
reait -b /usr/bin/true -s -n
Found /usr/bin/true:elf-x86_64
[
  {
    "distance": 0.0,
    "sha_256_hash": "1d20d8b1bbc861a2e9e0216efb7945fba664a5e6ba5f6a93febd6612a92551a8"
  },
  {
    "distance": 0.04410748228394201,
    "sha_256_hash": "265cb456cf5a09ad82380cb98118fb9255a9c9407085677d597abd828a5f4b11"
  },
  {
    "distance": 0.04710724400903421,
    "sha_256_hash": "1de9c70e46b17a96ee15e88e52da260de4f2d70e167c5172c29416d16f907482"
  },
  {
    "distance": 0.047961843853272956,
    "sha_256_hash": "01bf5e0f03dfaf6324f7e00942fed88ca52845c190a7392b0d0eb5c3a91091df"
  },
  {
    "distance": 0.05086539098571474,
    "sha_256_hash": "62dd31307316ee0e910eb845f35bf548b7fd79dc9f407ef917efdf14d143842e"
  }
]
```


## Configuration
`reait` reads the config file stored at `~/.reait.toml`. An example config file looks like:

```shell
apikey = "l1br3"
host = "https://api.reveng.ai"
model = "binnet-0.3-x86"
```

## Contact
Connect with us by filling out the contact form at [RevEng.AI](https://reveng.ai).

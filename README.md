# reait

## <ins>R</ins>ev<ins>E</ins>ng.<ins>AI</ins> <ins>T</ins>oolkit

Analyse compiled executable binaries using the RevEng.AI API. This tool allows you to search for similar components across different compiled executable programs, identify known vulnerabilities in stripped executables, and generate "YARA-like" AI signatures for entire binary files. More details about the API can be found at [docs.reveng.ai](https://docs.reveng.ai).

NB: We are in Alpha. We support GNU/Linux ELF and Windows PE executables for x86_64, and focus our support for x86_64 Linux ELF executables. 

## Installation

Install the latest stable version using pip.

`pip install reait`

### Latest development version

`pip install -e .`

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

### RevEng.AI embedding models
To use specific RevEng.AI AI models, or for training custom models, use `-m` to specify the model. The default option is to use the latest development model. Available models are `binnet-0.1` and `dexter`.

`reait -b /usr/bin/true -m dexter -a`

### Software Composition Analysis
To identify known open source software components embedded inside a binary, use the `-C` flag.

#### Stripped Binary CVE Checker
To check for known vulnerabilities found with embedded software components, use `-c` or `--cves`.


### RevEng.AI Binary Signature
To generate an AI functional description of an entire binary file, use the `-S` flag. NB: Under development.


### Binary embedding
Produce a dumb fingerprint for the whole binary by calculating the arithmetic mean of all symbol embeddings.

`reait -b /usr/bin/true -s`



## Configuration

`reait` reads the config file stored at `~/.reait.toml`. An example config file looks like:

```
apikey = "l1br3"
host = "https://api.reveng.ai"
model = "binnet-0.1"
```

## Contact
Connect with us by filling out the contact form at [RevEng.AI](https://reveng.ai).

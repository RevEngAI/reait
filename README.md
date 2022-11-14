# reait
RevEng.AI Toolkit

Analyse compiled executable binaries using the RevEng.AI API. This tool allows you to search for similar components inside compiled executable programs.

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
Once an analysis is complete, you may access RevEng.AI's BinNet embeddings for all symbols extracted with the `-x` flag.

`reait -b /usr/bin/true -x > embeddings.json`

##### Extract embedding for symbol at vaddr 0x19f0
`reait -b /usr/bin/true -x | jq ".[] | select(.vaddr==$((0x19f0))).embedding" > embedding.json`

### Search for similar symbols based on JSON embedding file
To query our database of similar symbols based on an embedding, use `-n` to search using Approximate Nearest Neighbours. The `--nns` allows you to specify the number of results returned.

`reait -e embedding.json -n`

## Contact
Connect with us by filling out the contact form at [RevEng.AI](https://reveng.ai).

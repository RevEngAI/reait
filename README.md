# reait
RevEng.AI Toolkit

Analyse compiled executable binaries using the RevEng.AI API. This tool allows you to search for similar components across different compiled executable programs. More details about the API can be found at [docs.reveng.ai](https://docs.reveng.ai).

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


### Search for similar symbols based on JSON embedding file
To query our database of similar symbols based on an embedding, use `-n` to search using Approximate Nearest Neighbours. The `--nns` allows you to specify the number of results returned. A list of symbol names and the distance between each vector is returned. 

`reait -e embedding.json -n`

NB: A smaller distance indicates a higher degree of similarity.

## Configuration

`reait` reads the config file stored at `~/.reait.toml`. An example config file looks like:

```
apikey = "l1br3"
host = "https://api.reveng.ai"
```

## Contact
Connect with us by filling out the contact form at [RevEng.AI](https://reveng.ai).

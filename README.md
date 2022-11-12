# reait
RevEng.AI Toolkit

Analyse compiled executable binaries using the RevEng.AI API.

## Installation

Install the latest stable version using pip.

`pip install reait`

### Latest development version

`pip install -e .`

## Running reait

#### Analyse binary
`reait -b /usr/bin/true -a`

#### Extract symbol embeddings
`reait -b /usr/bin/true -x > embeddings.json`

#### Extract embedding for symbol at vaddr 0x19f0
`reait -b /usr/bin/true -x | jq ".[] | select(.vaddr==$((0x19f0))).embedding" > embedding.json`

#### Search for similar symbols based on JSON embedding file
`reait -e embedding.json -n`

## Contact
Connect with us by filling out the contact form at [RevEng.AI](https://reveng.ai).

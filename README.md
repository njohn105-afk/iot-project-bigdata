# IoT Project Big Data

## Goal
Compare existing query-processing methods against a proposed confidence-weighted method on uncertain IoT data.

## Pipeline
1. Parse raw pcap files into a structured baseline dataset
2. Inject uncertainty (packet loss, delays, missing values)
3. Run existing methods and proposed method
4. Compare results against ground truth

## Setup
1. Install miniconda or anaconda
		https://anaconda.com/download/success
	2. Clone the repo
	3. If using VSCode:
		Open Anaconda Prompt
			conda init powershell
			Close & open VSCode
	4. Create the environment:
		conda env create -f environment.yml
	5. Activate it
		conda activate iotproj

## Repo Structure
- data/raw: original pcap files
- data/processed: clean baseline datasets
- data/corrupted: uncertainty-injected datasets
- src/baseline: baseline creation
- src/injectors: uncertainty generation
- src/methods: comparison methods
- src/evaluation: metrics and experiments

The data/ folder is referenced in scripts/test.py, this folder can be created locally and updated with pcap or other files to read.
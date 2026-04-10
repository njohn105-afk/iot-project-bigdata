Setup:
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


The data/ folder is referenced in scripts/test.py, this folder can be created locally and updated with pcap or other files to read.
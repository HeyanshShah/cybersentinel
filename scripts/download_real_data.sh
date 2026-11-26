#!/usr/bin/env bash
# Downloads the Loghub OpenSSH dataset: ~655,000 real log lines from an internet-facing
# SSH server (LabSZ), Dec-Jan, full of real brute-force attacks. ~4.6 MB download.
# Source: Zhu et al., "Loghub: A Large Collection of System Log Datasets for AI-driven
# Log Analytics", ISSRE 2023. https://github.com/logpai/loghub  (research use)
set -euo pipefail
mkdir -p data
curl -L -o data/SSH.tar.gz "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
tar -xzf data/SSH.tar.gz -C data
echo "Done: data/SSH.log  ->  python -m sentinel analyze data/SSH.log"

.PHONY: install install-dev install-oss test lint smoke package clean

install:
	python -m pip install -U pip
	python -m pip install -e .

install-dev: install
	python -m pip install pytest

# Optional external adapters. Requires Go in PATH.
install-oss:
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	go install github.com/owasp-amass/amass/v4/...@master
	go install github.com/d3mondev/puredns/v2@latest
	go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

test:
	python -m pytest -q

lint:
	python -m compileall -q dnsRecon

smoke:
	dnsRecon --version
	dnsRecon --examples
	dnsRecon doctor
	dnsRecon example.com --fast --quiet
	dnsRecon example.com --fast --quiet --report json

package:
	cd .. && zip -r dnx-recon-v1.0.0.zip dnx-recon-v1 -x 'dnx-recon-v1/.pytest_cache/*' 'dnx-recon-v1/**/__pycache__/*' 'dnx-recon-v1/reports/*' 'dnx-recon-v1/*.egg-info/*'

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache reports *.egg-info build dist

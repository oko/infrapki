lint:
	find . -type f | xargs black

pex:
	pipenv lock -r > requirements.txt
	pex . -v -e infrapki.cli:infrapki -r requirements.txt -o infrapki.pex --disable-cache

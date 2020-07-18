lint:
	find infrapki -type f -name '*.py' | xargs isort
	find infrapki -type f -name '*.py' | xargs black

pex:
	pipenv lock -r > requirements.txt
	pex . -v -e infrapki.cli:infrapki -r requirements.txt -o infrapki.pex --disable-cache

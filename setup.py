import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="infrapki",  # Replace with your own username
    version="0.0.1",
    author="Jacob Okamoto",
    author_email="oko+github@oko.io",
    description="InfraPKI, a small toolkit for doing infrastructure PKI.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/oko/infrapki",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    entry_points={"console_scripts": ["infrapki=infrapki.cli:infrapki"]},
    python_requires=">=3.6",
)

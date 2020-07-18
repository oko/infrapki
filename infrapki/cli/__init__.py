import logging

import click

from .ca import cacli

logging.basicConfig()


@click.group("infrapki")
@click.option("--debug", "-d", is_flag=True)
def infrapki(debug):
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    pass


infrapki.add_command(cacli)

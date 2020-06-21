import click
import logging

logging.basicConfig()

from .ca import cacli


@click.group("infrapki")
@click.option("--debug", "-d", is_flag=True)
def infrapki(debug):
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    pass


infrapki.add_command(cacli)

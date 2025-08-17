from dataclasses import dataclass

import click
from _typeshed import Incomplete
from flext_core import FlextResult as FlextResult

from flext_ldif.models import FlextLdifEntry as FlextLdifEntry

from .api import FlextLdifAPI as FlextLdifAPI
from .config import FlextLdifConfig as FlextLdifConfig
from .constants import (
    FlextLdifDefaultValues as FlextLdifDefaultValues,
    FlextLdifOperationMessages as FlextLdifOperationMessages,
)

@dataclass
class ParseCommandParams:
    input_file: str
    output: str | None
    max_entries: int | None
    validate: bool = ...
    stats: bool = ...

@dataclass
class TransformCommandParams:
    input_file: str
    output_file: str
    filter_type: str | None
    sort: bool = ...

def safe_click_echo(message: str, *, err: bool = False) -> None: ...

logger: Incomplete
MAX_DISPLAYED_ERRORS: int

def create_api_with_config(*, max_entries: int | None = None) -> FlextLdifAPI: ...
def apply_filter(
    api: FlextLdifAPI, entries: list[FlextLdifEntry], filter_type: str
) -> list[FlextLdifEntry]: ...
def handle_validation_errors(entries: list[FlextLdifEntry]) -> None: ...
def display_statistics(
    ctx: click.Context, api: FlextLdifAPI, entries: list[FlextLdifEntry]
) -> None: ...
def write_entries_to_file(
    api: FlextLdifAPI, entries: list[FlextLdifEntry], output_path: str
) -> None: ...
@click.pass_context
def cli(ctx: click.Context, /, **options: object) -> None: ...
@click.pass_context
def parse(
    ctx: click.Context,
    /,
    input_file: str,
    output: str | None,
    max_entries: int | None,
    **flags: object,
) -> None: ...
@click.pass_context
def validate(
    ctx: click.Context, input_file: str, *, strict: bool, schema: str | None
) -> None: ...
@click.pass_context
def transform(
    ctx: click.Context,
    input_file: str,
    output_file: str,
    filter_type: str | None,
    *,
    sort: bool,
) -> None: ...
@click.pass_context
def stats(ctx: click.Context, input_file: str, stats_format: str) -> None: ...
@click.pass_context
def find(
    ctx: click.Context,
    input_file: str,
    query: str | None,
    search_dn: str | None,
    search_attr: str | None,
) -> None: ...
@click.pass_context
def filter_by_class(
    ctx: click.Context, input_file: str, objectclass: str, output: str | None
) -> None: ...
@click.pass_context
def convert(ctx: click.Context, input_file: str, output_format: str) -> None: ...
@click.pass_context
def config_check(ctx: click.Context) -> None: ...
@click.pass_context
def write(
    ctx: click.Context, input_file: str, output: str | None, line_wrap: int
) -> None: ...
def setup_cli() -> object: ...
def main() -> None: ...

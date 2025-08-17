from _typeshed import Incomplete

ALLOWED_COMMANDS: set[str]

def run_cli_command(command_args: list[str]) -> tuple[int, str, str]: ...

class CliIntegrationDemonstrator:
    sample_file: Incomplete
    output_file: Incomplete
    json_output: Incomplete
    def __init__(self) -> None: ...
    def demonstrate_all(self) -> None: ...

def main() -> None: ...

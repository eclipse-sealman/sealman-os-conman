#!/usr/bin/env python3
#
# Copyright (c) 2025 Contributors to the Eclipse Foundation.
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License, Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
import importlib
import sys
from pathlib import Path
from typing import Any, Dict

import click


class ClickAnalyzer:
    """Analyze Click CLI structure to extract commands and options."""

    def analyze_click_app(self, app_module_path: str) -> Dict[str, Any]:
        """
        Analyze a Click application and extract its structure.

        Args:
            app_module_path: Module path like 'mpa.device.device:cli'

        Returns:
            Dictionary with commands, options, and completion data
        """
        try:
            module_name, attr_name = app_module_path.split(":")
            module = importlib.import_module(module_name)
            cli_obj = getattr(module, attr_name)

            if not isinstance(cli_obj, (click.Group, click.Command)):
                raise ValueError(f"{app_module_path} is not a Click command or group")

            return self._analyze_command(cli_obj, is_root=True)

        except Exception as e:
            print(f"Error analyzing Click app: {e}", file=sys.stderr)
            sys.exit(1)

    def _analyze_command(
        self, cmd: click.Command, is_root: bool = False, parent_name: str = ""
    ) -> Dict[str, Any]:
        """Recursively analyze Click commands and groups."""
        result: Dict[str, Any] = {
            "name": cmd.name or "main",
            "options": [],
            "subcommands": {},
            "choice_options": {},
            "file_options": set(),
            "dir_options": set(),
            "is_group": isinstance(cmd, click.Group),
            "dynamic_completion": getattr(cmd, "dynamic_completion", False),
            "choice_arguments": [],
        }

        command_is_dynamic = result["dynamic_completion"]

        for param in cmd.params:
            if isinstance(param, click.Option):
                if getattr(param, "hidden", False):
                    continue

                opts = param.opts + param.secondary_opts
                result["options"].extend(opts)

                if command_is_dynamic:
                    continue

                if isinstance(param.type, click.Choice):
                    choices = list(param.type.choices)
                    for opt in opts:
                        result["choice_options"][opt] = sorted(choices)

                if isinstance(param.type, (click.File, click.Path)):
                    for opt in opts:
                        if isinstance(param.type, click.Path):
                            if param.type.dir_okay and not param.type.file_okay:
                                result["dir_options"].add(opt)
                            else:
                                result["file_options"].add(opt)
                        else:
                            result["file_options"].add(opt)

            elif isinstance(param, click.Argument) and isinstance(
                param.type, click.Choice
            ):
                choices = list(param.type.choices)
                result["choice_arguments"].append(
                    {"name": param.name, "choices": sorted(choices)}
                )

        result["options"] = sorted(set(result["options"]))

        if isinstance(cmd, click.Group):
            for subcmd_name, subcmd in cmd.commands.items():
                if getattr(subcmd, "hidden", False):
                    continue

                full_name = (
                    f"{parent_name}.{subcmd_name}" if parent_name else subcmd_name
                )
                result["subcommands"][subcmd_name] = self._analyze_command(
                    subcmd, parent_name=full_name
                )

        return result


class BashCompletionGenerator:
    """Generate bash completion scripts from Click app structure."""

    def __init__(
        self, app_name: str, cli_structure: Dict[str, Any], app_module_path: str
    ):
        self.app_name = app_name
        self.structure = cli_structure
        self.app_module_path = app_module_path

    def _sanitize_name(self, name: str) -> str:
        """Sanitize command names for bash variable names."""
        return name.replace("-", "_").replace(".", "_")

    def generate(self) -> str:
        """Generate the complete bash completion script."""
        template = """#!/bin/bash

# Hybrid bash completion script for {app_name}
# Generated automatically - do not edit manually
# Usage: source this file or add to ~/.bash_completion.d/

_{app_name_sanitized}_completion() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    # Global options
    local global_opts="{global_opts}"

    # Subcommands
    local subcommands="{subcommands}"

{subcommand_declarations}

{completion_logic}

    return 0
}}

# Register the completion function
complete -F _{app_name_sanitized}_completion {app_name}
"""

        return template.format(
            app_name=self.app_name,
            app_name_sanitized=self._sanitize_name(self.app_name),
            global_opts=" ".join(sorted(self.structure["options"])),
            subcommands=" ".join(sorted(self.structure["subcommands"].keys())),
            subcommand_declarations=self._generate_all_declarations(),
            completion_logic=self._generate_completion_logic(),
        )

    def _generate_all_declarations(self) -> str:
        """Generate all variable declarations for commands and subcommands."""
        lines: list[str] = []

        def process_commands(
            commands: Dict[str, Dict[str, Any]], prefix: str = ""
        ) -> None:
            for cmd_name, cmd_data in sorted(commands.items()):
                sanitized_name = self._sanitize_name(cmd_name)
                # Generate basic command variables
                self._generate_command_vars(lines, prefix, sanitized_name, cmd_data)

                # Generate choice argument expansions
                if cmd_data.get("choice_arguments"):
                    self._generate_choice_expansions(
                        lines, prefix, sanitized_name, cmd_data, 0
                    )

                # Process real subcommands
                if cmd_data.get("subcommands"):
                    nested_prefix = f"{prefix}{sanitized_name}_"
                    process_commands(cmd_data["subcommands"], nested_prefix)

        process_commands(self.structure["subcommands"])
        return "\n".join(lines)

    def _generate_command_vars(
        self,
        lines: list[str],
        prefix: str,
        sanitized_name: str,
        cmd_data: Dict[str, Any],
    ) -> None:
        """Generate basic variables for a command."""
        var_name = f"{prefix}{sanitized_name}_opts"
        opts = " ".join(sorted(cmd_data["options"]))
        lines.append(f'    local {var_name}="{opts}"')

        # Generate choice options (for options)
        if cmd_data.get("choice_options"):
            for name, choices in cmd_data["choice_options"].items():
                if name.startswith("-"):
                    choice_var = f"{prefix}{sanitized_name}_choice_{self._sanitize_name(name.lstrip('-'))}"
                    choices_str = " ".join(choices)
                    lines.append(f'    local {choice_var}="{choices_str}"')

        # Generate file/dir options
        if cmd_data.get("file_options"):
            file_var = f"{prefix}{sanitized_name}_file_opts"
            file_opts = " ".join(sorted(cmd_data["file_options"]))
            lines.append(f'    local {file_var}="{file_opts}"')

        if cmd_data.get("dir_options"):
            dir_var = f"{prefix}{sanitized_name}_dir_opts"
            dir_opts = " ".join(sorted(cmd_data["dir_options"]))
            lines.append(f'    local {dir_var}="{dir_opts}"')

        # Generate dynamic flag
        if cmd_data.get("dynamic_completion"):
            dynamic_var = f"{prefix}{sanitized_name}_dynamic"
            lines.append(f'    local {dynamic_var}="true"')

        # Generate subcommands (including first choice argument)
        subcmds = []
        if cmd_data.get("subcommands"):
            subcmds.extend(sorted(cmd_data["subcommands"].keys()))
        if cmd_data.get("choice_arguments"):
            # Add first choice argument options as subcommands
            subcmds.extend(cmd_data["choice_arguments"][0]["choices"])

        if subcmds:
            subcmd_var_name = f"{prefix}{sanitized_name}_subcommands"
            subcmds_str = " ".join(sorted(set(subcmds)))
            lines.append(f'    local {subcmd_var_name}="{subcmds_str}"')

    def _generate_choice_expansions(
        self,
        lines: list[str],
        prefix: str,
        sanitized_name: str,
        cmd_data: Dict[str, Any],
        arg_index: int,
    ) -> None:
        """Recursively generate expansions for choice arguments."""
        if arg_index >= len(cmd_data["choice_arguments"]):
            return

        current_arg = cmd_data["choice_arguments"][arg_index]

        # For each choice in the current argument, create a "subcommand"
        for choice in current_arg["choices"]:
            choice_sanitized = self._sanitize_name(choice)
            choice_prefix = f"{prefix}{sanitized_name}_{choice_sanitized}"

            # Create a pseudo-command data that inherits parent properties
            choice_cmd_data = {
                "options": cmd_data["options"],
                "choice_options": cmd_data["choice_options"],
                "file_options": cmd_data["file_options"],
                "dir_options": cmd_data["dir_options"],
                "choice_arguments": cmd_data["choice_arguments"][
                    arg_index + 1:
                ],  # Remaining args
                "subcommands": cmd_data.get("subcommands", {}),
            }

            # Generate variables for this choice
            self._generate_command_vars(lines, choice_prefix, "", choice_cmd_data)

            # Recursively handle remaining choice arguments
            if choice_cmd_data["choice_arguments"]:
                self._generate_choice_expansions(
                    lines, choice_prefix, "", choice_cmd_data, 0
                )

    def _generate_completion_logic(self) -> str:
        """Generate the main completion logic."""
        return f"""    # Function to call dynamic completion when needed
    call_dynamic_completion() {{
        local IFS=$'\\n'
        local response
        response=$(env COMP_WORDS="${{COMP_WORDS[*]}}" COMP_CWORD=$COMP_CWORD _{
            self._sanitize_name(self.app_name).upper()
        }_COMPLETE=bash_complete {self.app_name.replace("-", "_")})

        for completion in $response; do
            IFS=',' read type value <<< "$completion"
            if [[ $type == 'dir' ]]; then
                COMPREPLY=()
                compopt -o dirnames
                return
            elif [[ $type == 'file' ]]; then
                COMPREPLY=()
                compopt -o default
                return
            elif [[ $type == 'plain' ]]; then
                COMPREPLY+=("$value")
            fi
        done
    }}

    # Enhanced function to get current command path (includes choice arguments)
    get_command_path() {{
        local path=""
        local i
        for ((i=1; i < COMP_CWORD; i++)); do
            local word="${{COMP_WORDS[i]}}"
            # Skip options
            if [[ $word == -* ]]; then
                continue
            fi

            # Check if this word is a command/choice at current level
            local current_commands
            if [[ -z "$path" ]]; then
                current_commands="$subcommands"
            else
                # Get subcommands for current path
                local var_name="${{path}}_subcommands"
                current_commands="${{!var_name:-}}"
            fi

            if [[ " $current_commands " =~ " $word " ]]; then
                if [[ -z "$path" ]]; then
                    path="$(echo "$word" | sed 's/-/_/g')"
                else
                    path="${{path}}_$(echo "$word" | sed 's/-/_/g')"
                fi
            else
                break
            fi
        done
        echo "$path"
    }}

    local command_path=$(get_command_path)

    # Check if we need dynamic completion for the current command
    if [[ -n "$command_path" ]]; then
        local dynamic_var="${{command_path}}_dynamic"
        local is_dynamic="${{!dynamic_var:-false}}"

        # If current command needs dynamic completion
        if [[ "$is_dynamic" == "true" ]]; then
            call_dynamic_completion
            return 0
        fi
    fi

    # If we're completing after the main command but no command path yet
    if [[ -z "$command_path" ]]; then
        if [[ ${{cur}} == -* ]]; then
            # Complete global options
            COMPREPLY=($(compgen -W "${{global_opts}}" -- ${{cur}}))
        else
            # Complete top-level subcommands
            COMPREPLY=($(compgen -W "${{subcommands}}" -- ${{cur}}))
        fi
        return 0
    fi

    # Get options and subcommands for current command path
    local opts_var="${{command_path}}_opts"
    local subcmds_var="${{command_path}}_subcommands"
    local file_opts_var="${{command_path}}_file_opts"
    local dir_opts_var="${{command_path}}_dir_opts"

    local current_opts="${{!opts_var:-}}"
    local current_subcmds="${{!subcmds_var:-}}"
    local file_opts="${{!file_opts_var:-}}"
    local dir_opts="${{!dir_opts_var:-}}"

    # Handle file/directory completion
    if [[ " $file_opts " =~ " $prev " ]]; then
        COMPREPLY=()
        compopt -o default
        return 0
    elif [[ " $dir_opts " =~ " $prev " ]]; then
        COMPREPLY=()
        compopt -o dirnames
        return 0
    fi

    # Handle choice options (for option values)
    local choice_var="${{command_path}}_choice_$(echo "${{prev}}" | sed 's/^-*//; s/-/_/g')"
    local choices="${{!choice_var:-}}"
    if [[ -n "$choices" ]]; then
        COMPREPLY=($(compgen -W "${{choices}}" -- ${{cur}}))
        return 0
    fi

    if [[ ${{cur}} == -* ]]; then
        # Complete options for current command
        COMPREPLY=($(compgen -W "${{current_opts}}" -- ${{cur}}))
    elif [[ -n "$current_subcmds" ]]; then
        # Complete subcommands (including choice arguments)
        COMPREPLY=($(compgen -W "${{current_subcmds}}" -- ${{cur}}))
    fi"""


@click.command()
@click.option(
    "--app",
    "-a",
    required=True,
    help="Click app module path (e.g., mpa.device.device:cli)",
)
@click.option(
    "--output", "-o", help="Output file path (default: <appname>_completion.sh)"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(app: str, output: str, verbose: bool) -> None:
    """Generate hybrid bash completion script for Click CLI applications."""

    if verbose:
        click.echo(f"Analyzing Click app: {app}")

    module_part = app.split(":")[0]
    app_name = module_part.split(".")[-1].replace("_", "-")

    analyzer = ClickAnalyzer()

    try:
        cli_structure = analyzer.analyze_click_app(app)
        if verbose:
            click.echo(f"CLI name: {app_name}")
            click.echo(f"Found {len(cli_structure['subcommands'])} subcommands")
            click.echo(f"Found {len(cli_structure['options'])} global options")

            def show_structure(cmd_data: Dict[str, Any], level: int = 0) -> None:
                indent = "  " * level
                for subcmd_name, subcmd_data in cmd_data.get("subcommands", {}).items():
                    is_group = subcmd_data.get("is_group", False)
                    is_dynamic = subcmd_data.get("dynamic_completion", False)
                    choice_args = subcmd_data.get("choice_arguments", [])

                    indicators = []
                    if is_group:
                        indicators.append("group")
                    if is_dynamic:
                        indicators.append("dynamic")
                    if choice_args:
                        arg_names = [arg["name"] for arg in choice_args]
                        indicators.append(f"choice_args: {', '.join(arg_names)}")

                    indicator_str = f" ({'; '.join(indicators)})" if indicators else ""
                    click.echo(f"{indent}- {subcmd_name}{indicator_str}")

                    if subcmd_data.get("subcommands"):
                        show_structure(subcmd_data, level + 1)

            if cli_structure["subcommands"]:
                click.echo("Command structure:")
                show_structure(cli_structure, 1)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)

    if not output:
        output = f"{app_name}-complete.bash"

    generator = BashCompletionGenerator(app_name, cli_structure, app)
    completion_script = generator.generate()
    output_path = Path(output)
    try:
        output_path.write_text(completion_script)
        output_path.chmod(0o755)

        click.echo(f"Generated hybrid completion script: {output_path}")
        click.echo(f"To use: source {output_path}")
        click.echo(f"Or copy to: ~/.bash_completion.d/{output_path.name}")

    except Exception as e:
        click.echo(f"Error writing file: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

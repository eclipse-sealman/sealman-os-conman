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
"""
Argparse class with customized default help formatters, extended
methods add_argument(), parse_args() and private method
_get_all_dests_and_verify_their_uniqueness(). It has the functionality to
verify that 'dests' (names of arguments in the Namespace) are unique within
parser and all of its subparsers. This prevents silent overwrite of parser
arguments by it's subparsers. Note that 'help' argument is ignored.
"""

# Standard imports
import argparse
import textwrap

from typing import Type, Any


class ExamplesFormatter(argparse.HelpFormatter):
    def _fill_text(self, text: str, width: int, indent: str) -> str:
        if not text.startswith("examples:"):
            return super()._fill_text(text, width, indent)
        subsequent_indent = indent + '    '
        retval = ''
        for example in text.split('***'):
            if len(retval) == 0:
                retval += example
            else:
                retval += '\n'
                command, separator, description = example.partition(' --- ')
                description = self._whitespace_matcher.sub(' ', description).strip()
                retval += textwrap.fill(
                    self._prog + command + separator + description,
                    initial_indent=indent,
                    subsequent_indent=subsequent_indent,
                )
        return retval

    def _metavar_formatter(self, action: Any, default_metavar: Any) -> Any:
        if action.metavar is not None:
            result = action.metavar
        elif action.choices is not None:
            choice_strs: list[str] = []
            for choice in action.choices:
                if isinstance(action, argparse._SubParsersAction):
                    subparser = action.choices[choice]
                    if isinstance(subparser, ArgumentParser) and subparser.hidden:
                        continue
                choice_strs.append(str(choice))
            result = '{%s}' % ','.join(choice_strs)
        else:
            result = default_metavar

        def format(tuple_size: Any) -> Any:
            if isinstance(result, tuple):
                return result
            else:
                return (result, ) * tuple_size
        return format

    def add_argument(self, action: Any) -> Any:
        if isinstance(action, argparse._SubParsersAction):
            keys = [key for key, subparser in action.choices.items() if subparser.hidden]
            action._choices_actions = [action for action in action._choices_actions if action.dest not in keys]

        super().add_argument(action)


class ArgumentParser(argparse.ArgumentParser):
    def __init__(
        self,
        *,
        formatter_class: Type[argparse.HelpFormatter] = ExamplesFormatter,
        hidden: bool = False,
        **kwdargs: Any,
    ):
        super().__init__(formatter_class=formatter_class, **kwdargs)
        self.action_dests: set[str] = set()
        self.hidden = hidden

    def add_argument(self, *args: Any, **kwargs: Any) -> argparse.Action:
        action = super().add_argument(*args, **kwargs)
        if isinstance(action, argparse._HelpAction) is False:
            self.action_dests.add(action.dest)
        return action

    def _get_all_dests_and_verify_their_uniqueness(self) -> set[str]:
        """
        Get dests from all of subparsers and make sure the are unique.
        Throw a ValueError if they are not.
        """
        sub_dests = set()
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, subparser in action.choices.items():
                    sub_dests |= subparser._get_all_dests_and_verify_their_uniqueness()
                    if len(d := self.action_dests & sub_dests):
                        raise ValueError(
                            f"Arguments {d} of subparser {name!r} already exist in the Namespace.\n"
                            "Change the value of the 'dest' keyword argument."
                        )
        return self.action_dests | sub_dests

    def parse_args(self, *args: Any, **kwargs: Any) -> Any:
        self._get_all_dests_and_verify_their_uniqueness()
        return super().parse_args(*args, **kwargs)

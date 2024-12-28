from typing import Any, Sequence
import argparse


class DangrArgparse(argparse.ArgumentParser):
    """
    Custom argument parser for the 'dangr' project.

    Provides the cli for all the arguments needed for the dangr_rt and
    allows the user to add other arguments if needed.

    In the resulting parserd arguments a `config` dictionary is
    accesible. That same dict can be recieved by any DangrAnalysis.
    """
    def __init__(self, description: str) -> None:
        super().__init__(description=description)
        self._config: dict[str, Any] = {}

        self._add_dangr_argument(
            "reverse",
            "-r",
            "--reverse",
            type=bool,
            default=None,
            help="Whether or not to reverse memory, by default this depends on the binary arch."
        )

        self._add_dangr_argument(
            "max_depth",
            "-d",
            "--max-depth",
            type=int,
            default=None,
            help="Maximum depth for backward execution."
        )

        self._add_dangr_argument(
            "timeout",
            "-t",
            "--timeout",
            type=int,
            default=None,
            help="Timeout for dangr simulation step."
        )

        self._add_dangr_argument(
            "num_finds",
            "-n",
            "--num-finds",
            type=int,
            default=None,
            help="Number of findings expected for each dangr simulation step. "
                "If this number is reached, the simulation will stop, "
                "otherwise it will excetute until there are no more active states"
        )

        self._add_dangr_argument(
            "cfg_call_depth",
            "-c",
            "--cfg-call-depth",
            type=int,
            default=None,
            help="How deep in the call stack to analyze dependencies"
        )

        self._add_dangr_argument(
            "cfg_max_steps",
            "-s",
            "--cfg-max-steps",
            type=int,
            default=None,
            help="The maximum number of basic blocks to recover forthe longest path"
                 " when constructing the cfg for the dependency analysis."
        )

        self._add_dangr_argument(
            "cfg_resolve_indirect_jumps",
            "-j",
            "--cfg-resolve-indirect-jumps",
            type=int,
            default=None,
            help="Whether to enable the indirect jump resolvers for resolving indirect jumps"
                 "for dependency analysis"
        )

    def _add_dangr_argument(self, config_key: str, *args: Any, **kwargs: Any) -> None:
        self._config[config_key] = str(kwargs.get('default'))
        super().add_argument(*args, **kwargs)

    def dangr_parse_args(
        self,
        args: Sequence[str] | None = None,
        namespace: argparse.Namespace | None = None
    ) -> argparse.Namespace:
        """
        Parses arguments, updates the config dictionary only with fixed argument values,
        and attaches config as an attribute of the returned namespace.
        """
        parsed_args = self.parse_args(args, namespace)

        for key in self._config:
            if hasattr(parsed_args, key):
                self._config[key] = getattr(parsed_args, key)

        setattr(parsed_args, "config", self._config)
        return parsed_args

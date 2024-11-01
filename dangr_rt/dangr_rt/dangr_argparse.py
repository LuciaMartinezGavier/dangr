from typing import Any, Sequence
import argparse


class DangrArgparse(argparse.ArgumentParser):
    """
    Custom argument parser for the 'dangr' project.

    Provides the cli for all the arguments needed for the dangr_rt and
    allows the user to add other arguments if needed.

    In the resulting parserd arguments a `config` dictionary is
    accesible. That same dict can be recieved by the DangrAnalysis.
    """
    def __init__(self, description: str) -> None:
        super().__init__(description=description)
        self._config: dict[str, Any] = {}

        self._add_dangr_argument(
            "max_depth",
            "-d",
            "--max-depth",
            type=int,
            default=None,
            help="Maximum depth for backward execution."
        )

    def _add_dangr_argument(self, config_key: str, *args: Any, **kwargs: Any) -> None:
        self._config[config_key] = str(kwargs.get('default'))
        super().add_argument(*args, **kwargs)

    def dangr_parse_args(
        self,
        args: Sequence[str] | None,
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
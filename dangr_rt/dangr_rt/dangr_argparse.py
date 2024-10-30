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
        self._config: dict = {}

        self._add_dangr_argument(
            "max_depth",
            "-d",
            "--max-depth",
            type=int,
            default=None,
            help="Maximum depth for backward execution."
        )

    def _add_dangr_argument(self, config_key: str, *args, **kwargs):
        self._config[config_key] = kwargs.get('default')
        super().add_argument(*args, **kwargs)

    def parse_args(self, args=None, namespace=None):
        """
        Parses arguments, updates the config dictionary only with fixed argument values,
        and attaches config as an attribute of the returned namespace.
        """
        parsed_args = super().parse_args(args, namespace)

        for key in self._config:
            if hasattr(parsed_args, key):
                self._config[key] = getattr(parsed_args, key)

        setattr(parsed_args, "config", self._config)
        return parsed_args

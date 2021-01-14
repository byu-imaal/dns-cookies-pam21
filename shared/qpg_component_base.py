from abc import *
from typing import Any, List, Type


class QnameComponent(ABC):
    """
    Base class for defining a component for use in QueryParserGenerator
    To create a custom component you must inherit from this class and define `id`, `exceptions`
    `generate()` and optionally `parse()`

    Note that when defining `generate()` kwargs should be replaced with specific named arguments
    e.g. generate(cls, a, b, c=2). This allows for reflection when passing kwargs into the QueryParserGenerator

    For examples, see `qpg_defaults.py` which defines a number of QnameComponents that are built-in to
    QueryParserGenerator
    """

    """ The ID to use in a format_str. e.g. $ip"""
    id: str

    """ A list of exceptions that can be thrown by the encode and decode methods"""
    exceptions: List[Type[Exception]]

    @classmethod
    @abstractmethod
    def generate(cls, **kwargs) -> str:
        """
        Defines how to generate this label. Additional arguments can be passed in, but should
        be explicitly defined with a name in the child class

        :param kwargs: the argument needed to generate this label. DO NOT use kwargs, replace with explicit names
        :return: the label to put in the qname
        """
        pass

    @classmethod
    def parse(cls, label) -> Any:
        """
        Defines how to parse a generated label. In many cases there is nothing to undo (e.g. a hostname), in which
        case this method is sufficient. If there is a process to undoing, define this method in the child class

        :param label: the label to parse. Should directly come from the `generate()` method
        :return: the appropriate value, likely matching the type of parameters for the `generate()` function
        """
        return label

    # BELOW METHODS SHOULD NOT BE EXTENDED / OVERRIDDEN

    @classmethod
    def get_all_args(cls) -> List[str]:
        """
        :return: a list of all args for the `generate()` function
        """
        return list(cls.generate.__code__.co_varnames[1:])

    @classmethod
    def get_required_args(cls):
        """
        :return: a list of all required (meaning they have no default) args for the `generate()` function
        """
        varnames = list(cls.generate.__code__.co_varnames)
        return varnames[1:len(varnames) - len(cls.generate.__defaults__ or [])]

    @classmethod
    def get_optional_args(cls):
        """
        :return: a list of all optional (meaning they have a default) args for the `generate()` function
        """
        varnames = list(cls.generate.__code__.co_varnames)
        return varnames[len(varnames) - len(cls.generate.__defaults__ or []):]

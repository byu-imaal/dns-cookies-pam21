"""QPG == (Q)name-(P)arser-(G)enerator"""

from typing import List, Type
from shared.qpg_defaults import *
from shared.qpg_component_base import QnameComponent
from collections import OrderedDict


class QPGException(BaseException):
    """Generic QPG exception"""


class LabelMappingDoesNotExist(QPGException):
    """Raised when an attempt is made to access (use. delete, etc.) a label mapping that does not exist"""


class MissingArgument(QPGException):
    """Raised when an argument for some component is not provided in the `gen` kwargs"""


class LabelDoesNotMatch(QPGException):
    """Raised when a given query name doesn't match the defined label string"""


class QnameParserGenerator:
    key_indicator: str = '$'
    label_str: str = ''
    label_components: List[Type[QnameComponent]] = \
        [QnameKeyword, QnameIP, QnameHostname, QnameTimestamp, QnameMicroSeconds, QnameUnique,
         QnameRandomAlpha, QnameRandomAlphaNumeric, QnameRandomNumeric, QnameRandomBase32]

    @classmethod
    def __label_keys(cls) -> List[str]:
        if '.' in cls.label_str:
            return cls.label_str.split('.')
        if cls.label_str == '':
            return []
        return [cls.label_str]

    @classmethod
    def __get_component(cls, label_key: str) -> Type[QnameComponent]:
        component = next((component for component in cls.label_components if component.id == label_key), None)
        if component is None:
            raise LabelMappingDoesNotExist(f'"{label_key}" is not defined as a label string. \
                                (Hint: you might need to add a QnameComponent subclass to `label_components`)')
        else:
            return component

    @classmethod
    def __get_kwargs_for_component(cls, given_kwargs: dict, component: Type[QnameComponent]) -> dict:
        kwargs = {}
        for arg in component.get_required_args():
            if arg not in given_kwargs:
                raise MissingArgument(f'Missing kwarg of "{arg}" for component "{component.id}"')
            kwargs[arg] = given_kwargs[arg]

        for opt_arg in component.get_optional_args():
            if opt_arg in given_kwargs:
                kwargs[opt_arg] = given_kwargs[opt_arg]
        return kwargs

    @classmethod
    def gen(cls, domain: str, **kwargs) -> str:
        """Generate a query name given the domain name and key word arguments (kwargs)

        This function uses the class variable *format_str* to construct the query name.

        :param domain: a ``str``, the domain to be used as the base for the query name
        :param kwargs: a ``dict``, the key word arguments needed to generate the labels of the query name
        """
        output_labels = []
        for label_key in cls.__label_keys():
            if not label_key.startswith(cls.key_indicator):
                output_labels.append(label_key)
                continue

            _component = cls.__get_component(label_key)
            _kwargs = cls.__get_kwargs_for_component(kwargs, _component)
            output_labels.append(_component.generate(**_kwargs))
        output_labels.append(domain)
        return '.'.join(output_labels)

    @classmethod
    def parse(cls, qname: str) -> OrderedDict:
        """Parse a query name into a tuple of its decoded labels.
        :param qname: a ``str``, the query name to parse
        :return: a ``tuple`` of the decoded labels
        """
        output_labels = OrderedDict()
        for label_key, label in zip(cls.__label_keys(), qname.split('.')):
            if not label_key.startswith(cls.key_indicator):
                if label != label_key:
                    raise LabelDoesNotMatch(f'expected {label_key}, got {label}')
                output_labels[label] = label
                continue
            _component = cls.__get_component(label_key)
            parsed_label = _component.parse(label)
            output_labels[label_key] = parsed_label
        return output_labels

    @classmethod
    def list_expected_kwargs(cls) -> str:
        out_str = ""
        for label_key in cls.__label_keys():
            if label_key.startswith(cls.key_indicator):
                component = cls.__get_component(label_key)
                out_str += "{:10}{}\n".format(component.id, component.get_all_args())
        return out_str

# Example code:
# subclass QueryParserGenerator and set the label_str


# class MyQueryParserGenerator(QnameParserGenerator):
#     label_str = "$ip.$test"
#
#     class MyComponent(QnameComponent):
#         id = "$test"
#         exceptions = []
#
#         @classmethod
#         def encode(cls) -> str:
#             return "hellothere"
#
#     label_components = QnameParserGenerator.label_components + [MyComponent]
#
#
# class AnotherOne(QnameParserGenerator):
#     label_str = "$ip.$ts.$tsu.$host.$uniq.$randnum"
#
#
# if __name__ == '__main__':
#     for ip in ['1.1.1.1', '8.8.8.8', '9.9.9.9', '1.2.3.4', '128.187.22.25']:
#         qname = AnotherOne.gen('example.com', ip_addr=ip)
#         print(qname)
#         parts = AnotherOne.parse(qname)
#         print(parts)


# Copyright (c) 2012 Giorgos Verigakis <verigak@gmail.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# See https://github.com/jonathaneunice/colors for original code

import re
from functools import partial
from typing import Union, List

# Supported colors
FG_COLORS = {'none': None, 'black': 30, 'dk_red': 31, 'dk_green': 32, 'dk_yellow': 33, 'dk_blue': 34, 'dk_magenta': 35,
             'dk_cyan': 36, 'gray': 37, 'dk_gray': 90, 'red': 91, 'green': 92, 'yellow': 93, 'blue': 94,
             'magenta': 95, 'cyan': 96, 'white': 97}
BG_COLORS = {name: (color + 10 if color is not None else None) for name, color in FG_COLORS.items()}

# ANSI style names
STYLES = {'none': None, 'bold': 1, 'faint': 2, 'italic': 3, 'underline': 4, 'blink': 5, 'crossed': 9}


def color(inp: str, fg: str = None, bg: str = None, style: Union[str, List[str]] = None) -> str:
    """
    Surrounds inp with the ANSI codes to achieve the specified foreground color, background color, and styles.

    :param inp: the string to color
    :param fg: the desired foreground color. One of ``FG_COLORS``
    :param bg: the desired background color. One of ``BG_COLORS``
    :param style: the desired style. One of ``STYLES``
    :return: ``inp`` with the appropriate ANSI codes applied at the beginning and cleared at the end
    """
    codes = []

    if fg:
        fg = fg.strip().lower()
        if fg not in FG_COLORS.keys():
            raise KeyError("Not a valid foreground color. Options are: {}".format(FG_COLORS.keys()))
        codes.append(FG_COLORS[fg])
    if bg:
        bg = bg.strip().lower()
        if bg not in BG_COLORS.keys():
            raise KeyError("Not a valid background color. Options are: {}".format(FG_COLORS.keys()))
        codes.append(BG_COLORS[bg])
    if style:
        if isinstance(style, str):
            style = [style]
        for s in style:
            s = s.strip().lower()
            if s not in STYLES.keys():
                raise KeyError("Not a valid style. Options are: {}".format(STYLES.keys()))
            codes.append(STYLES[s])

    if codes:
        return '\x1b[{}m{}\x1b[0m'.format(';'.join(str(c) for c in codes if c is not None), inp)
    else:
        return inp


def strip_color(inp: str) -> str:
    """
    Remove ANSI color/style sequences from a string. May not catch obscure codes used outside this module.

    :param inp: the string to strip
    :return: ``inp`` with ansi codes removed
    """
    return re.sub('\x1b\\[(K|.*?m)', '', inp)


# Foreground color shortcuts
black = partial(color, fg='black')
gray = partial(color, fg='gray')
red = partial(color, fg='red')
green = partial(color, fg='green')
yellow = partial(color, fg='yellow')
blue = partial(color, fg='blue')
magenta = partial(color, fg='magenta')
cyan = partial(color, fg='cyan')
white = partial(color, fg='white')

# Style shortcuts
bold = partial(color, style='bold')
faint = partial(color, style='faint')
italic = partial(color, style='italic')
underline = partial(color, style='underline')
blink = partial(color, style='blink')
crossed = partial(color, style='crossed')

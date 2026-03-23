# Copyright 2022 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Changes the values such as 32'hx into 32'h0. Takes into account multiple digits and when x is not the first digit.
# Assumes that the number is expressed in hexadecimal, which seems to always be the case for the Yosys outputs.

import multiprocessing as mp
import re
import sys

# sys.argv[1]: path to source cellift.sv
# sys.argv[2]: path to target cellift.sv file where the initial constant xs are replaced with zeros.

CONST_REGEX = r"(\d'[a-zA-Z0-9_]*)x"

if __name__ == "__main__":
    global cellift_in_lines
    cellift_in_path =  sys.argv[1]
    cellift_out_path = sys.argv[2]

    with open(cellift_in_path, "r") as f:
        content = f.read()

    while True:
        content, num_replacements = re.subn(CONST_REGEX, r"\g<1>0", content)
        if not num_replacements:
            break

    with open(cellift_out_path, "w") as f:
        f.write(content)

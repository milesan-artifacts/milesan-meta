# Copyright 2024 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Remove occurrences of CLK_t0. This is useful for openc910 with hybridift.

import sys
import re
# sys.argv[1]: source file path.
# sys.argv[2]: target file path.

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Takes 2 arguments: the Verilog source file path, the Verilog target file path.")

    with open(sys.argv[1], "r") as f:
        verilog_content = f.read()

    verilog_lines = verilog_content.split('\n')
    n_lines = len(verilog_lines)
    verilog_lines = list(filter(lambda x: '.CLK_t0' not in x and '.PortAClk_t0' not in x, verilog_lines))
    # verilog_lines = list(filter(lambda x: len(re.findall('\..*clk_t0\(',x, re.IGNORECASE)) == 0, verilog_lines))
    print(f"Removed {n_lines - len(verilog_lines)} lines.")
    with open(sys.argv[2], "w") as f:
        f.write('\n'.join(verilog_lines))

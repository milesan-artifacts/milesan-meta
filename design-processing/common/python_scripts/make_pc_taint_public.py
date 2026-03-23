# Copyright 2022 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import re
import sys

# sys.argv[1]: source Verilog file
# sys.argv[2]: target Verilog file
# sys.argv[3:]: pc taint signal names, for example pc_id_t0. Can be preceded by an index, for example 0:pc_id_t0 will take the first declaration

if __name__ == "__main__":
    src_filename = sys.argv[1]
    tgt_filename = sys.argv[2]
    pc_taint_signal_names = sys.argv[3:]

    with open(src_filename, "r") as f:
        verilog_content = f.read()

    for pc_taint_signal_name in pc_taint_signal_names:
        if ':' in pc_taint_signal_name:
            declaration_index = int(pc_taint_signal_name.split(':')[0])
            pc_taint_signal_name = pc_taint_signal_name.split(':')[1]
        else:
            declaration_index = None

        pc_taint_regex = r"((?:wire|reg|logic)\s*\[\d+:[01]\]\s*"+pc_taint_signal_name+r"\s*);"
        print(f"Regex: {pc_taint_regex}")

        # There should be exactly one declaration of the PC taint
        all_declarations = re.findall(pc_taint_regex, verilog_content)
        if declaration_index is None and len(all_declarations) != 1:
            raise ValueError(f"Expected exactly 1 declaration of {pc_taint_signal_name}. Got {len(all_declarations)} instead.")
        elif declaration_index is not None and len(all_declarations) <= declaration_index:
            raise ValueError(f"Expected at least {declaration_index+1} declaration(s) of {pc_taint_signal_name}. Got {len(all_declarations)} instead.")

        print(f"Found {len(all_declarations)} declaration(s) of {pc_taint_signal_name}.")

        # Substitute by adding the /* verilator public */ meta-comment.
        verilog_content = re.sub(pc_taint_regex, all_declarations[0 if declaration_index is None else declaration_index] + ' /* verilator public */;', verilog_content)

    with open(tgt_filename, "w") as f:
        f.write(verilog_content)

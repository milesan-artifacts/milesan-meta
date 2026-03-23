# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Remove a single interface declaration from given SystemVerilog file.

import re
import sys

# sys.argv[1]: source file path.
# sys.argv[2]: target file path (will be a copy of the source file, but without the specified interfaces).
# sys.argv[3]: name of the top interface to remove.
# sys.argv[4]: number of expected occurrences of the interface.

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Takes 4 arguments: the Verilog source file path, the Verilog target file path, the interface name to remove and the number of expected interface declarations.")

    with open(sys.argv[1], "r") as f:
        verilog_content = f.read()        

    interface_name = sys.argv[3]
    num_expected_occurrences = int(sys.argv[4])
    num_found_occurrences = len(re.findall("interface(\s|\n)+{}(\s|\n)*(\(|#|import)(.|\n)+?endinterface[^\n]*\n".format(interface_name), verilog_content))
    if num_found_occurrences != num_expected_occurrences:
        print(f"WARNING: Found `{num_found_occurrences}` occurrences of declarations of interface `{sys.argv[3]}`, expected `{num_expected_occurrences}`.")
    # Remove the first occurrence of the interface declaration
    verilog_content, num_subs = re.subn("interface(\s|\n)+{}(\s|\n)*(\(|#|import)(.|\n)+?endinterface[^\n]*\n".format(interface_name), "\n", verilog_content, 1, flags=re.MULTILINE|re.DOTALL) # Weakness: does not ignore comments.
    print("  Removed {}/{} occurrence of interface {}.".format(num_subs, num_expected_occurrences, interface_name))

    with open(sys.argv[2], "w") as f:
        f.write(verilog_content)

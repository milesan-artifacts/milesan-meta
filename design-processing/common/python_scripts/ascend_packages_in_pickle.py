# Copyright 2023 Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# Move the packages up in the pickle files, works in place.

import re
import sys

# sys.argv[1]: source and target pickle Verilog file

REGEX = r"package \w+?;.+?endpackage.*?\n"

if __name__ == "__main__":
    src_filename = sys.argv[1]

    with open(src_filename, "r") as f:
        content = f.read()

    # Get the package texts
    packagetexts = re.findall(REGEX, content, re.DOTALL)

    def get_package_name(packagetext):
        match = re.match(r"package (\w+);", packagetext)
        return match.group(1)

    # Create a dependency graph for the packages
    dependencies = {}
    for packagetext in packagetexts:
        package_name = get_package_name(packagetext)
        dependencies[package_name] = set(name.replace(":", "") for name in re.findall(r"\b(\w+)::", packagetext))

    # Topologically sort the packages
    sorted_packages = []
    visited = set()

    def visit(package):
        if package in visited:
            return
        visited.add(package)
        for dep in dependencies.get(package, []):
            visit(dep)
        sorted_packages.append(package)

    for package in dependencies:
        visit(package)

    # Reorder the package texts based on the sorted order
    package_dict = {re.match(r"package (\w+);", text).group(1): text for text in packagetexts}
    packagetexts = [package_dict[name] for name in sorted_packages]

    for packagetext in packagetexts:
        print(f"Ascend {packagetext.splitlines()[0]}")
    # Remove them from the pickle
    content = re.sub(REGEX, '\n/* removed */\n', content, flags=re.DOTALL)

    # Write them to the top of the pickle file
    content = '\n\n'.join(packagetexts) + content

    with open(src_filename, "w") as f:
        f.write(content)

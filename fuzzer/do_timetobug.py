# Copyright 2024 Tobias Kovats, Flavien Solt, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

# This script evaluates the duration to detect each bug.

# sys.argv[1]: design name
# sys.argv[2]: num of cores allocated to fuzzing
# sys.argv[3]: offset for seed (to avoid running the fuzzing on the same instances over again)
# sys.argv[4]: authorize privileges (by default 1)

from top.fuzzdesigntiming import measure_time_to_bug, plot_bug_timings
from milesan.toleratebugs import tolerate_bug_for_bug_timing

from params.runparams import PATH_TO_TMP
import json
import os

bug_designs = {
    'p1': 'picorv32',
    'p2': 'picorv32',
    'p3': 'picorv32',
    'p4': 'picorv32',
    'p5': 'picorv32-p5',
    'p6': 'picorv32',
    'v1': 'vexriscv-v1-7',
    'v2': 'vexriscv-v1-7',
    'v3': 'vexriscv-v1-7',
    'v4': 'vexriscv-v1-7',
    'v5': 'vexriscv-v1-7',
    'v6': 'vexriscv-v1-7',
    'v7': 'vexriscv-v1-7',
    'v8': 'vexriscv-v8-9-v15',
    'v9': 'vexriscv-v8-9-v15',
    'v10': 'vexriscv-v10-11',
    'v11': 'vexriscv-v10-11',
    'v12': 'vexriscv-v12',
    'v13': 'vexriscv-v13',
    'v14': 'vexriscv',
    'v15': 'vexriscv-v8-9-v15',
    'k1': 'kronos-k1',
    'k2': 'kronos-k2',
    'k3': 'kronos',
    'k4': 'kronos',
    'k5': 'kronos',
    'c1': 'cva6-c1',
    'c2': 'cva6',
    'c3': 'cva6',
    'c4': 'cva6',
    'c5': 'cva6',
    'c6': 'cva6',
    'c7': 'cva6',
    'c8': 'cva6',
    'c9': 'cva6',
    'b1': 'boom-b1',
    'b2': 'boom',
    'r1': 'rocket',
    'y1': 'cva6-y1',
}

if __name__ == '__main__':
    if "MILESAN_ENV_SOURCED" not in os.environ:
        raise Exception("The Cascade environment must be sourced prior to running the Python recipes.")

    NUM_WORKERS = 64
    NUM_REPS = 10

    # Measure the time to detect each bug.

    # TODO Uncomment
    # for bug_name, design_name in bug_designs.items():
    #     tolerate_bug_for_bug_timing(design_name, bug_name, True)
    #     ret = measure_time_to_bug(design_name, NUM_WORKERS, NUM_REPS)
    #     tolerate_bug_for_bug_timing(design_name, bug_name, False)

    #     retpath = os.path.join(PATH_TO_TMP, f"bug_timings_{bug_name}_{NUM_WORKERS}_{NUM_REPS}.json")
    #     json.dump(ret, open(retpath, "w"))
    #     print('Saved bug timing results to', retpath)

    # Plot these measurements.
    plot_bug_timings(NUM_WORKERS, NUM_REPS)

else:
    raise Exception("This module must be at the toplevel.")

#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Nokia

TEST_DIR="${TEST_DIR:-$(dirname $0)}"
MODEL_FILE=$TEST_DIR/conv.bin

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

# Skip test if model file is not found. The model file is compiled separately.
# See platform/linux-dpdk/example/ml/conv_gen.sh.

if [ ! -e "$MODEL_FILE" ]; then
        echo "SKIP: ML model file ($MODEL_FILE) not found"
        exit $TEST_SKIPPED
fi

$TEST_DIR/ml_dpdk $MODEL_FILE

if [ $? -ne 0 ] ; then
    echo Test FAILED
    exit 1
fi

exit 0

#!/bin/sh -ex
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Nokia

#
# This script requires the onnx python module. The mrvl-mlc and mlModel tools
# are expected to be in PATH. These tools are x86-64 binaries, so this script
# must be run on an x86-64 machine. However, the model can only be run on a
# machine equipped with the Marvell machine learning inference processor (MLIP).
#

python ./conv_gen.py
mrvl-mlc conv.onnx conv --num_tiles=1 --batch=1
mv bin_conv/conv.bin .
rm -rf bin_conv compiler_dir profile
mlModel -M -m conv.bin

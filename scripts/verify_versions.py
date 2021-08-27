# -*- coding: utf-8 -*-
# cython: language_level=3
# BSD 3-Clause License
#
# Copyright (c) 2021, Faster Speeding
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""Script used to verify that the versions for a repo match up."""
import argparse
import logging
import pathlib

import packaging.version
import pyproject_parser

_LOGGER = logging.getLogger("verify_versions")


def check(
    pyproject_path: pathlib.Path = pathlib.Path("./pyproject.toml"),
    *,
    required_version: packaging.version.Version | None = None,
) -> bool:
    """Check that the versions match up."""
    import tanjun

    pyproject = pyproject_parser.PyProject.load(str(pyproject_path.absolute()))
    linked_version = packaging.version.parse(tanjun.__version__)

    if not pyproject.project or not (pp_version := pyproject.project.get("version", None)):
        raise RuntimeError("Missing project version definition in pyproject.toml")

    if linked_version != pp_version:
        _LOGGER.error("Pyproject.toml version is %s but tanjun version is %s", pp_version, tanjun.__version__)
        return False

    if required_version and required_version != pp_version:
        _LOGGER.error("Expected version not found: found %s but expected %s", pp_version, required_version)
        return False

    _LOGGER.info("Versions match (%s)", linked_version)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify set versions")
    parser.add_argument(
        "--required-version", "-r", default=None, type=packaging.version.Version, help="The required version"
    )
    parser.add_argument(
        "--pyproject-path",
        "-p",
        default=pathlib.Path("./pyproject.toml"),
        type=pathlib.Path,
        help="The path to the pyproject.toml file",
    )
    args = parser.parse_args()

    result = check(args.pyproject_path, required_version=args.required_version)

    exit(int(not result))

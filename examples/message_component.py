# -*- coding: utf-8 -*-
# cython: language_level=3
# BSD 3-Clause License
#
# Copyright (c) 2020-2021, Faster Speeding
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
"""Basic usage of Tanjun's message command system."""
import time

import tanjun

component = tanjun.Component()


@component.with_command
@tanjun.as_message_command("ping")
async def ping(ctx: tanjun.abc.Context, /) -> None:
    # As a note, for brevity any hidden Discord REST error handling logic hasn't been included here.
    # For more information on how Discord REST errors may be handled see
    # https://fasterspeeding.github.io/Yuyo/backoff.html
    start_time = time.perf_counter()
    await ctx.respond(content="Nyaa master!!!")
    time_taken = (time.perf_counter() - start_time) * 1_000
    heartbeat_latency = ctx.shards.heartbeat_latency * 1_000 if ctx.shards else float("NAN")
    await ctx.edit_last_response(f"PONG\n - REST: {time_taken:.0f}ms\n - Gateway: {heartbeat_latency:.0f}ms")


@tanjun.as_message_command_group("note", "notes")
async def note(ctx: tanjun.abc.Context) -> None:
    await ctx.respond("You have zero notes")


@note.with_command
@tanjun.with_greedy_argument("value")
@tanjun.with_argument("name")
@tanjun.with_parser
@tanjun.as_message_command("add", "create")
async def note_add(ctx: tanjun.abc.Context, name: str, value: str) -> None:
    ...  # Actual implementation
    await ctx.respond(f"Added {name} note with value {value}")


@note.with_command
@tanjun.with_option("force", "--force", "-f", converters=(bool,), default=False)
@tanjun.with_argument("name")
@tanjun.with_parser
@tanjun.as_message_command("remove", "delete")
async def note_remove(ctx: tanjun.abc.Context, name: str, force: bool) -> None:
    ...  # Actual implementation
    await ctx.respond(f"Force removed {name} note" if force else f"Removed {name} note")


# Here we define a loader which can be used to easily load this example
# components into a bot from a link (assuming the environment has all the
# right configurations setup.)
@tanjun.as_loader
def load_examples(client: tanjun.abc.Client) -> None:
    client.add_component(component.copy())
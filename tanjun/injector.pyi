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
from __future__ import annotations

import abc
import typing

from . import traits

_T = typing.TypeVar("_T")
CallbackT = typing.Callable[..., typing.Union[_T, typing.Awaitable[_T]]]
GetterCallbackT = typing.Callable[["traits.Context"], _T]

class Getter(typing.Generic[_T]):
    __slots__: typing.Sequence[str]
    callback: GetterCallbackT[_T]
    is_async: typing.Optional[bool]
    name: str
    def __init__(self, callback: GetterCallbackT[_T], name: str, /) -> None: ...

class Undefined:
    def __new__(cls) -> Undefined: ...

UNDEFINED: typing.Final[Undefined]
UndefinedOr = typing.Union[Undefined, _T]

def check_injecting(callback: CallbackT[typing.Any], /) -> bool: ...
@typing.overload
def Injected(*, callback: typing.Callable[[], typing.Awaitable[_T]]) -> _T: ...
@typing.overload
def Injected(*, callback: typing.Callable[[], _T]) -> _T: ...
@typing.overload
def Injected(*, type: UndefinedOr[_T]) -> _T: ...
async def call_getters(
    ctx: traits.Context, getters: typing.Iterable[Getter[typing.Any]]
) -> typing.Mapping[str, typing.Any]: ...

class InjectorClient:
    __slots__: typing.Sequence[str]
    def __init__(self, client: traits.Client, /) -> None: ...
    def add_type_dependency(self, type_: typing.Type[_T], value: _T, /) -> None: ...
    def get_type_dependency(self, type_: typing.Type[_T], /) -> UndefinedOr[_T]: ...
    def add_callable_override(self, callback: CallbackT[_T], override: CallbackT[_T], /) -> None: ...
    def get_callable_override(self, callback: CallbackT[_T], /) -> typing.Optional[CallbackT[_T]]: ...
    def _get_component_mapping(self) -> typing.Dict[typing.Type[traits.Component], traits.Component]: ...
    def _make_callback_getter(self, callback: CallbackT[_T], name: str, /) -> Getter[CallbackT[_T]]: ...
    def _make_type_getter(self, type_: typing.Type[_T], name: str, /) -> Getter[_T]: ...
    def resolve_callback_to_getters(
        self, callback: CallbackT[typing.Any], /
    ) -> typing.Iterator[Getter[typing.Any]]: ...

class Injectable(abc.ABC):
    __slots__: typing.Sequence[str]
    @abc.abstractmethod
    def needs_injector(self) -> bool: ...
    @abc.abstractmethod
    def set_injector(self, client: InjectorClient, /) -> None: ...

class InjectableCheck(Injectable):
    __slots__: typing.Sequence[str]
    callback: CallbackT[bool]
    injector: typing.Optional[InjectorClient]
    is_async: typing.Optional[bool]
    def __init__(self, callback: CallbackT[bool], *, injector: typing.Optional[InjectorClient] = None) -> None: ...
    async def __call__(self, ctx: traits.Context, /) -> bool: ...
    @property
    def needs_injector(self) -> bool: ...
    def set_injector(self, client: InjectorClient) -> None: ...

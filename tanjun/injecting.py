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

__all__: list[str] = [
    "AbstractInjectionContext",
    "BasicInjectionContext",
    "CallbackDescriptor",
    "cache_callback",
    "CallbackSig",
    "Undefined",
    "UNDEFINED",
    "UndefinedOr",
    "injected",
    "Injected",
    "InjectorClient",
    "Injectable",
]

import abc
import asyncio
import collections.abc as collections
import copy
import inspect
import typing

import hikari
from hikari import traits as hikari_traits

from . import abc as tanjun_abc
from . import conversion
from . import errors

if typing.TYPE_CHECKING:
    _BaseInjectableValueT = typing.TypeVar("_BaseInjectableValueT", bound="BaseInjectableValue[typing.Any]")

_InjectorClientT = typing.TypeVar("_InjectorClientT", bound="InjectorClient")
_T = typing.TypeVar("_T")
CallbackSig = collections.Callable[..., tanjun_abc.MaybeAwaitableT[_T]]
CallbackSigT = typing.TypeVar("CallbackSigT", bound=CallbackSig[typing.Any])  # TODO: use


class Undefined:
    __instance: Undefined

    def __bool__(self) -> typing.Literal[False]:
        return False

    def __new__(cls) -> Undefined:
        try:
            return cls.__instance

        except AttributeError:
            new = super().__new__(cls)
            assert isinstance(new, Undefined)
            cls.__instance = new
            return cls.__instance


UNDEFINED: typing.Final[Undefined] = Undefined()
UndefinedOr = typing.Union[Undefined, _T]


class AbstractInjectionContext(abc.ABC):
    __slots__ = ()

    @abc.abstractmethod
    def client(self) -> InjectorClient:
        raise NotImplementedError

    @abc.abstractmethod
    def cache_result(self, callback: CallbackSig[_T], value: _T, /) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def get_cached_result(self, callback: CallbackSig[_T], /) -> UndefinedOr[_T]:
        raise NotImplementedError

    @abc.abstractmethod
    def get_type_special_case(self, type_: type, /) -> UndefinedOr[_T]:
        raise NotImplementedError


class BasicInjectionContext(AbstractInjectionContext):
    __slots__ = ("_client", "_result_cache")

    def __init__(self, client: InjectorClient, /) -> None:
        self._client = client
        self._result_cache: dict[CallbackSig[typing.Any], typing.Any]

    def client(self) -> InjectorClient:
        return self._client

    def cache_result(self, callback: CallbackSig[_T], value: _T, /) -> None:
        self._result_cache[callback] = value

    def get_cached_result(self, callback: CallbackSig[_T], /) -> UndefinedOr[_T]:
        return self._result_cache.get(callback, UNDEFINED)

    def get_type_special_case(self, _: type[_T], /) -> UndefinedOr[_T]:
        return UNDEFINED


class CallbackDescriptor:
    __slots__ = ("descriptors", "is_async", "type")

    def __init__(
        self,
        callback: typing.Optional[CallbackSig[typing.Any]] = None,
        type: typing.Optional[_TypeT[typing.Any]] = None,
    ) -> None:
        self.is_async: typing.Optional[bool] = None
        if callback is None:
            if type is None:
                raise ValueError("Either callback or type must be specified")

            self.callback: typing.Optional[tuple[CallbackSig[typing.Any], dict[str, CallbackDescriptor]]] = None
            self.type: typing.Optional[_TypeT[typing.Any]] = type

        if type is not None:
            raise ValueError("Only one of type or callback should be passed")

        self.type = None

        try:
            parameters = inspect.signature(callback).parameters.items()
        except ValueError:  # If we can't inspect it then we have to assume this is a NO
            self.callback = (callback, {})
            return

        descriptors: dict[str, CallbackDescriptor] = {}
        for name, parameter in parameters:
            if parameter.default is parameter.empty or not isinstance(parameter.default, Injected):
                continue

            if parameter.kind is parameter.POSITIONAL_ONLY:
                raise ValueError("Injected positional only arguments are not supported")

            if parameter.default.callback is not None:
                descriptors[name] = CallbackDescriptor(callback=parameter.default.callback)

            else:
                assert parameter.default.type is not None
                descriptors[name] = CallbackDescriptor(type=parameter.default.type)

        self.callback = (callback, descriptors)

    @staticmethod
    async def _resolve_type(ctx: AbstractInjectionContext, type_: type[_T]) -> _T:
        if dependency := ctx.client.get_type_dependency(type_):
            if (cached_result := ctx.get_cached_result(dependency)) is not UNDEFINED:
                return cached_result

            result = await dependency(ctx)
            ctx.cache_result(dependency, result)
            return result

        if (special_case := ctx.get_type_special_case(type_)) is not UNDEFINED:
            return special_case

        raise errors.MissingDependencyError(f"Couldn't resolve injected type {type_} to actual value") from None

    @property
    def needs_injector(self) -> bool:
        return bool(self.callback[1]) if self.callback else True

    async def resolve(self, ctx: AbstractInjectionContext, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        if self.type is not None:
            return await self._resolve_type(ctx, self.type)(ctx)

        assert self.callback is not None
        if override := ctx.client.get_callback_override(self.callback):
            return await override(ctx, *args, **kwargs)

        if (result := ctx.get_cached_result(self.callback)) is not UNDEFINED:
            return result

        if not self.needs_injector:
            result = self.callback(*args, **kwargs)
            ctx.cache_result(self.callback, result)
            return result

        sub_results = {name: await descriptor.resolve(ctx) for name, descriptor in self.callback[1].items()}
        result = self.callback[0](*args, **sub_results, **kwargs)
        if self.is_async is None:
            self.is_async = isinstance(collections.Awaitable, result)

        if self.is_async:
            assert isinstance(collections.Awaitable, result)
            result = await result

        ctx.cache_result(self.callback, result)
        return result


_TypeT = type[_T]


class Injected(typing.Generic[_T]):
    __slots__ = ("callback", "_descriptor", "type")

    def __init__(
        self,
        *,
        callback: typing.Optional[CallbackSig[_T]] = None,
        type: typing.Optional[_TypeT[_T]] = None,  # noqa: A002
    ) -> None:  # TODO: add default/factory to this?
        if callback is None and type is None:
            raise ValueError("Must specify one of `callback` or `type`")

        if callback is not None and type is not None:
            raise ValueError("Only one of `callback` or `type` can be specified")

        self.callback = callback
        self._descriptor = CallbackDescriptor(callback=callback, type=type)
        self.type = type


def injected(
    *,
    callback: typing.Optional[CallbackSig[_T]] = None,
    type: typing.Optional[_TypeT[_T]] = None,  # noqa: A002
) -> Injected[_T]:
    return Injected(callback=callback, type=type)


class InjectorClient:
    __slots__ = ("_callback_overrides", "_client", "_type_dependencies")

    def __init__(self, client: tanjun_abc.Client, /) -> None:
        self._callback_overrides: dict[CallbackSig[typing.Any], InjectableValue[typing.Any]] = {}
        self._client = client
        self._type_dependencies: dict[type[typing.Any], InjectableValue[typing.Any]] = {}

    def add_type_dependency(self: _InjectorClientT, type_: type[_T], callback: CallbackSig[_T], /) -> _InjectorClientT:
        self._type_dependencies[type_] = InjectableValue(callback, injector=self)
        return self

    def get_type_dependency(self, type_: type[_T], /) -> typing.Optional[CallbackSig[_T]]:
        return self._type_dependencies.get(type_)

    def get_type_special_case(self, type_: type[_T], /) -> UndefinedOr[_T]:
        if issubclass(type_, InjectorClient):
            return type_

        return UNDEFINED

    def remove_type_dependency(self, type_: type[_T], /) -> None:
        del self._type_dependencies[type_]

    def add_callback_override(
        self: _InjectorClientT, callback: CallbackSig[_T], override: CallbackSig[_T], /
    ) -> _InjectorClientT:
        self._callback_overrides[callback] = InjectableValue(override, injector=self)
        return self

    def get_callback_override(self, callback: CallbackSig[_T], /) -> typing.Optional[CallbackSig[_T]]:
        return self._callback_overrides.get(callback)

    def remove_callback_override(self, callback: CallbackSig[_T], /) -> None:
        del self._callback_overrides[callback]

    async def _resolve_type(self, ctx: AbstractInjectionContext, type_: type[_T]) -> _T:
        try:
            callback = self._type_dependencies[type_]

        except KeyError:
            if (special_case := ctx.get_type_special_case(type_)) is not UNDEFINED:
                return special_case

            raise errors.MissingDependencyError(f"Couldn't resolve injected type {type_} to actual value") from None

        else:
            return callback(ctx)

    async def resolve_callback(
        self, ctx: AbstractInjectionContext, descriptor: CallbackDescriptor, /, *args: typing.Any, **kwargs: typing.Any
    ) -> typing.Any:
        raise NotImplementedError


_TYPE_SPECIAL_CASES: dict[
    type[typing.Any],
    collections.Callable[[tanjun_abc.Context, InjectorClient], UndefinedOr[typing.Any]],
] = {
    tanjun_abc.Client: lambda ctx, _: ctx.client,
    tanjun_abc.Component: lambda ctx, _: ctx.component or UNDEFINED,
    tanjun_abc.Context: lambda ctx, _: ctx,
    InjectorClient: lambda _, cli: cli,
    hikari.api.Cache: lambda ctx, _: ctx.cache or UNDEFINED,
    hikari.api.RESTClient: lambda ctx, _: ctx.rest,
    hikari_traits.ShardAware: lambda ctx, _: ctx.shards or UNDEFINED,
    hikari.api.EventManager: lambda ctx, _: ctx.events or UNDEFINED,
    hikari.api.InteractionServer: lambda ctx, _: ctx.server or UNDEFINED,
}


class Injectable(abc.ABC):
    __slots__ = ()

    @property
    @abc.abstractmethod
    def needs_injector(self) -> bool:
        ...

    @abc.abstractmethod
    def set_injector(self, client: InjectorClient, /) -> None:
        ...


class BaseInjectableValue(Injectable, typing.Generic[_T]):
    __slots__ = ("callback", "_descriptor", "_injector")

    def __init__(self, callback: CallbackSig[_T], *, injector: typing.Optional[InjectorClient] = None) -> None:
        self.callback = callback
        self._descriptor = CallbackDescriptor(callback)
        self._injector = injector

    # This is delegated to the callback in-order to delegate set/list behaviour for this class to the callback.
    def __eq__(self, other: typing.Any) -> bool:
        return bool(self.callback == other)

    # This is delegated to the callback in-order to delegate set/list behaviour for this class to the callback.
    def __hash__(self) -> int:
        return hash(self.callback)

    @property
    def needs_injector(self) -> bool:
        return self._descriptor.needs_injector

    def copy(self: _BaseInjectableValueT, *, _new: bool = True) -> _BaseInjectableValueT:
        if not _new:
            self.callback = copy.copy(self.callback)
            return self

        return copy.copy(self).copy(_new=False)

    def set_injector(self, client: InjectorClient, /) -> None:
        if self._injector:
            raise RuntimeError("Injector already set for this check")

        self._injector = client

    async def call(self, *args: typing.Any, ctx: tanjun_abc.Context) -> _T:
        if self.needs_injector:
            if self._injector is None:
                raise RuntimeError("Cannot call this injectable callback before the injector has been set")

            return await self._injector.resolve_callback(ctx, self._descriptor, *args)

        result = self.callback(*args)
        if isinstance(result, collections.Awaitable):
            return await result

        return result


class InjectableValue(BaseInjectableValue[_T]):
    __slots__ = ()

    async def __call__(self, ctx: AbstractInjectionContext, /) -> _T:
        return await self.call(ctx=ctx)


class InjectableCheck(BaseInjectableValue[bool]):
    __slots__ = ()

    async def __call__(self, ctx: tanjun_abc.Context, /) -> bool:
        if result := await self.call(ctx, ctx=ctx):
            return result

        raise errors.FailedCheck


class InjectableConverter(BaseInjectableValue[_T]):
    __slots__ = ("_is_base_converter",)

    def __init__(self, callback: CallbackSig[_T], *, injector: typing.Optional[InjectorClient] = None) -> None:
        super().__init__(callback, injector=injector)
        self._is_base_converter = isinstance(self.callback, conversion.BaseConverter)

    async def __call__(self, value: conversion.ArgumentT, ctx: tanjun_abc.Context, /) -> _T:
        if self._is_base_converter:
            assert isinstance(self.callback, conversion.BaseConverter)
            return typing.cast(_T, await self.callback(value, ctx))

        return await self.call(value, ctx=ctx)


class _CacheCallback(typing.Generic[_T]):
    __slots__ = ("_callback", "_lock", "_result")

    def __init__(self, callback: CallbackSig[_T], /) -> None:
        self._callback = CallbackDescriptor(callback)
        self._lock: typing.Optional[asyncio.Lock] = None
        self._result: typing.Union[_T, Undefined] = UNDEFINED

    async def __call__(
        self,
        # Positional arg(s) may be guaranteed under some contexts so we want to pass those through.
        *args: typing.Any,
        ctx: tanjun_abc.Context = Injected(type=tanjun_abc.Context),  # type: ignore[assignment]
        injector: InjectorClient = Injected(type=InjectorClient),  # type: ignore[assignment]
    ) -> _T:
        if self._result is not UNDEFINED:
            assert not isinstance(self._result, Undefined)
            return self._result

        if not self._lock:
            self._lock = asyncio.Lock()

        async with self._lock:
            if self._result is not UNDEFINED:
                assert not isinstance(self._result, Undefined)
                return self._result

            self._result = await injector.resolve_callback(ctx, self._callback, *args)

        assert not isinstance(self._result, Undefined)
        return self._result


def cache_callback(callback: CallbackSig[_T], /) -> collections.Callable[..., collections.Awaitable[_T]]:
    return _CacheCallback(callback)

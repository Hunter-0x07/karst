# Adapted from this repository, docs/mvp-v0.2@789b197296b677dffdda565462799390aa9f7e2a.
"""Only the M01 model/tool message contract; no task scheduler or tool executor."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import uuid4

from .errors import ProtocolError, RequestError


@dataclass(frozen=True, slots=True)
class ModelRequest:
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    request_id: str = field(default_factory=lambda: "model-" + uuid4().hex)


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str


@dataclass(frozen=True, slots=True)
class ModelReply:
    request_id: str
    provider_response_id: str | None
    model: str
    text: str
    tool_calls: tuple[ToolCall, ...]
    finish_reason: str
    usage: dict[str, int | None] | None
    attempts: int
    elapsed_seconds: float
    assistant_message: dict[str, Any] = field(repr=False)

    @property
    def is_truncated(self) -> bool:
        return self.finish_reason == "length"

    def to_assistant_message(self) -> dict[str, Any]:
        # Optional reasoning_content is replayed in memory for compatible gateways,
        # but is never printed or persisted by the diagnostic/probe layer.
        return deepcopy(self.assistant_message)


def _serializable(value: Any) -> None:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise RequestError("请求内容必须是有限、可序列化的 JSON。") from None


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON value")


def loads_json(value: str | bytes | bytearray) -> Any:
    from karst.config import strict_json, KarstError
    try:
        return strict_json(value)
    except KarstError as exc:
        raise ValueError("invalid strict JSON") from exc


def validate_request(request: ModelRequest) -> None:
    if not isinstance(request.request_id, str) or not request.request_id.strip():
        raise RequestError("request_id 不能为空。")
    if not isinstance(request.messages, list) or not request.messages:
        raise RequestError("messages 必须是非空列表。")
    pending: set[str] = set()
    for message in request.messages:
        if not isinstance(message, dict):
            raise RequestError("每条 message 必须是对象。")
        role = message.get("role")
        if not isinstance(role, str) or role not in {"system", "user", "assistant", "tool"}:
            raise RequestError("不支持的消息角色。")
        if pending and role != "tool":
            raise RequestError("必须先为全部工具调用提供结果，才能继续对话。")
        if role == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or call_id not in pending:
                raise RequestError("工具结果缺少匹配调用，或重复提供结果。")
            if not isinstance(message.get("content"), str):
                raise RequestError("工具结果 content 必须是字符串。")
            pending.remove(call_id)
        else:
            content = message.get("content")
            if role in {"system", "user"} and not isinstance(content, str):
                raise RequestError("system/user 消息必须有文本 content。")
            if content is not None and not isinstance(content, str):
                raise RequestError("M01 仅支持文本消息，暂不接收图像或内容块。")
            calls = message.get("tool_calls")
            if calls is not None:
                if role != "assistant" or not isinstance(calls, list) or not calls:
                    raise RequestError("tool_calls 只允许在 assistant 消息中使用非空列表。")
                for call in calls:
                    if not isinstance(call, dict) or call.get("type") != "function":
                        raise RequestError("只支持 function 工具调用。")
                    call_id = call.get("id")
                    function = call.get("function")
                    if not isinstance(call_id, str) or not call_id or call_id in pending:
                        raise RequestError("工具调用 ID 为空或重复。")
                    if not isinstance(function, dict) or not isinstance(function.get("name"), str) or not function["name"]:
                        raise RequestError("工具调用名称不合法。")
                    if not isinstance(function.get("arguments"), str):
                        raise RequestError("工具调用 arguments 必须是原始 JSON 字符串。")
                    pending.add(call_id)
    if pending:
        raise RequestError("仍有工具调用没有结果，不能发送到网关。")
    if request.tools is not None:
        if not isinstance(request.tools, list) or not request.tools:
            raise RequestError("tools 应为非空列表；不使用工具时设为 None。")
        names: set[str] = set()
        for tool in request.tools:
            if not isinstance(tool, dict) or tool.get("type") != "function":
                raise RequestError("tools 只支持 function 定义。")
            function = tool.get("function")
            if not isinstance(function, dict) or not isinstance(function.get("name"), str) or not function["name"] or function["name"] in names:
                raise RequestError("工具定义名称缺失或重复。")
            if not isinstance(function.get("parameters"), dict):
                raise RequestError("工具定义需要 parameters 对象。")
            names.add(function["name"])
    if request.tool_choice is not None:
        if not request.tools:
            raise RequestError("tool_choice 需要工具定义。")
        if isinstance(request.tool_choice, str):
            if request.tool_choice not in {"auto", "none", "required"}:
                raise RequestError("不支持的 tool_choice。")
        elif isinstance(request.tool_choice, dict):
            function = request.tool_choice.get("function")
            if request.tool_choice.get("type") != "function" or not isinstance(function, dict) or not isinstance(function.get("name"), str) or function["name"] not in names:
                raise RequestError("指定工具必须存在于 tools 定义。")
        else:
            raise RequestError("tool_choice 格式不合法。")
    _serializable(request.messages)
    _serializable(request.tools)
    _serializable(request.tool_choice)


def response_usage(payload: Any) -> dict[str, int | None] | None:
    """Usage belongs to an actual request even when its content cannot execute."""
    usage = payload.get("usage") if isinstance(payload, dict) else None
    if not isinstance(usage, dict):
        return None
    return {name: value if type(value := usage.get(name)) is int and value >= 0 else None
            for name in ("prompt_tokens", "completion_tokens", "total_tokens")}


def parse_reply(payload: Any, *, request_id: str, model: str, attempts: int, elapsed_seconds: float) -> ModelReply:
    if not isinstance(payload, dict) or not isinstance(payload.get("choices"), list) or len(payload["choices"]) != 1:
        raise ProtocolError("INVALID_CHOICES", "网关响应需要恰好一个 choices 项。")
    choice = payload["choices"][0]
    if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
        raise ProtocolError("INVALID_MESSAGE", "网关响应没有有效 assistant message。")
    message = choice["message"]
    if message.get("role", "assistant") != "assistant":
        raise ProtocolError("INVALID_ROLE", "响应消息角色不是 assistant。")
    if message.get("function_call") is not None:
        raise ProtocolError("LEGACY_FUNCTION_CALL", "网关返回旧版 function_call，M01 需要带 ID 的 tool_calls。")
    if message.get("refusal"):
        raise ProtocolError("MODEL_REFUSAL", "模型拒绝该请求，未把拒绝内容当作完成结果。")
    text = message.get("content")
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise ProtocolError("INVALID_CONTENT", "当前适配器只支持文本 content。")
    finish = choice.get("finish_reason")
    if not isinstance(finish, str) or not finish:
        raise ProtocolError("MISSING_FINISH_REASON", "网关没有明确的结束原因。")
    if finish == "content_filter":
        raise ProtocolError("CONTENT_FILTER", "网关阻止了该响应。")
    if finish not in {"stop", "tool_calls", "length"}:
        raise ProtocolError("UNSUPPORTED_FINISH_REASON", "网关返回了未支持的结束原因。")
    raw_calls = message.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, list):
        raise ProtocolError("INVALID_TOOL_CALLS", "tool_calls 必须是列表。")
    if raw_calls and finish == "length":
        raise ProtocolError("TRUNCATED_TOOL_CALLS", "工具请求被输出上限截断；本轮不能执行，请检查 Token 配置。")
    calls: list[ToolCall] = []
    seen: set[str] = set()
    for raw in raw_calls:
        if not isinstance(raw, dict) or raw.get("type") != "function":
            raise ProtocolError("INVALID_TOOL_CALL", "只支持 function 工具调用。")
        call_id = raw.get("id")
        function = raw.get("function")
        if not isinstance(call_id, str) or not call_id or call_id in seen:
            raise ProtocolError("INVALID_TOOL_ID", "网关工具调用 ID 缺失或重复。")
        if not isinstance(function, dict) or not isinstance(function.get("name"), str) or not function["name"]:
            raise ProtocolError("INVALID_TOOL_NAME", "网关工具调用名称缺失。")
        argument_text = function.get("arguments")
        if not isinstance(argument_text, str):
            raise ProtocolError("INVALID_ARGUMENTS", "网关工具参数必须是 JSON 字符串。")
        try:
            arguments = loads_json(argument_text)
        except (ValueError, RecursionError):
            raise ProtocolError("INVALID_ARGUMENTS", "网关工具参数不是有效 JSON；不会猜测修复。") from None
        if not isinstance(arguments, dict):
            raise ProtocolError("INVALID_ARGUMENTS", "工具参数 JSON 顶层必须是对象。")
        try:
            json.dumps(arguments, allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            raise ProtocolError("INVALID_ARGUMENTS", "工具参数包含非有限的 JSON 数值。") from None
        calls.append(ToolCall(call_id, function["name"], arguments, argument_text))
        seen.add(call_id)
    if finish == "tool_calls" and not calls:
        raise ProtocolError("INCONSISTENT_FINISH", "结束原因声明工具调用，但响应没有 tool_calls。")
    if not text.strip() and not calls:
        code = "TOKEN_LIMIT" if finish == "length" else "EMPTY_CONTENT"
        raise ProtocolError(code, "模型没有给出回答或工具请求；请检查输出Token限制及网关兼容性。")
    assistant: dict[str, Any] = {"role": "assistant", "content": message.get("content")}
    if calls:
        assistant["tool_calls"] = [
            {"id": call.id, "type": "function", "function": {"name": call.name, "arguments": call.raw_arguments}}
            for call in calls
        ]
    if isinstance(message.get("reasoning_content"), str):
        assistant["reasoning_content"] = message["reasoning_content"]
    usage = response_usage(payload)
    response_id = payload.get("id")
    return ModelReply(request_id, response_id if isinstance(response_id, str) else None,
                      payload.get("model") if isinstance(payload.get("model"), str) else model,
                      text, tuple(calls), finish, usage, attempts, elapsed_seconds, assistant)


def append_tool_results(history: list[dict[str, Any]], reply: ModelReply, results: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Build a complete next turn, preserving provider tool IDs and their order."""
    expected = {call.id for call in reply.tool_calls}
    if not expected or set(results) != expected:
        raise RequestError("必须为本轮每个工具 ID 提供恰好一个结果，不能遗漏或添加。")
    messages = deepcopy(history) + [reply.to_assistant_message()]
    for call in reply.tool_calls:
        value = results[call.id]
        _serializable(value)
        content = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, allow_nan=False)
        messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
    validate_request(ModelRequest(messages))
    return messages

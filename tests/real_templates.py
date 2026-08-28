"""Stock chat templates from mainstream model families (unmodified)."""

TEMPLATES = {}
TEMPLATES["llama3"] = (
    """{% set loop_messages = messages %}{% for message in loop_messages %}{% set content = '<|start_header_id|>' + message['role'] + '<|end_header_id|>\n\n'+ message['content'] | trim + '<|eot_id|>' %}{% if loop.index0 == 0 %}{% set content = bos_token + content %}{% endif %}{{ content }}{% endfor %}{% if add_generation_prompt %}{{ '<|start_header_id|>assistant<|end_header_id|>\n\n' }}{% endif %}"""
)

TEMPLATES["chatml_qwen"] = (
    """{% for message in messages %}{% if loop.first and messages[0]['role'] != 'system' %}{{ '<|im_start|>system\nYou are a helpful assistant.<|im_end|>\n' }}{% endif %}{{'<|im_start|>' + message['role'] + '\n' + message['content'] + '<|im_end|>' + '\n'}}{% endfor %}{% if add_generation_prompt %}{{ '<|im_start|>assistant\n' }}{% endif %}"""
)

TEMPLATES["mistral"] = (
    """{{ bos_token }}{% for message in messages %}{% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}{{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}{% endif %}{% if message['role'] == 'user' %}{{ '[INST] ' + message['content'] + ' [/INST]' }}{% elif message['role'] == 'assistant' %}{{ message['content'] + eos_token}}{% else %}{{ raise_exception('Only user and assistant roles are supported!') }}{% endif %}{% endfor %}"""
)

TEMPLATES["gemma"] = (
    """{{ bos_token }}{% if messages[0]['role'] == 'system' %}{{ raise_exception('System role not supported') }}{% endif %}{% for message in messages %}{% if (message['role'] == 'assistant') %}{% set role = 'model' %}{% else %}{% set role = message['role'] %}{% endif %}{{ '<start_of_turn>' + role + '\n' + message['content'] | trim + '<end_of_turn>\n' }}{% endfor %}{% if add_generation_prompt %}{{'<start_of_turn>model\n'}}{% endif %}"""
)

TEMPLATES["phi3"] = (
    """{% for message in messages %}{% if message['role'] == 'system' and message['content'] %}{{'<|system|>\n' + message['content'] + '<|end|>\n'}}{% elif message['role'] == 'user' %}{{'<|user|>\n' + message['content'] + '<|end|>\n'}}{% elif message['role'] == 'assistant' %}{{'<|assistant|>\n' + message['content'] + '<|end|>\n'}}{% endif %}{% endfor %}{% if add_generation_prompt %}{{ '<|assistant|>\n' }}{% else %}{{ eos_token }}{% endif %}"""
)

TEMPLATES["llama2"] = (
    """{% if messages[0]['role'] == 'system' %}{% set loop_messages = messages[1:] %}{% set system_message = messages[0]['content'] %}{% else %}{% set loop_messages = messages %}{% set system_message = false %}{% endif %}{% for message in loop_messages %}{% if loop.index0 == 0 and system_message != false %}{% set content = '<<SYS>>\n' + system_message + '\n<</SYS>>\n\n' + message['content'] %}{% else %}{% set content = message['content'] %}{% endif %}{% if message['role'] == 'user' %}{{ bos_token + '[INST] ' + content | trim + ' [/INST]' }}{% elif message['role'] == 'assistant' %}{{ ' ' + content | trim + ' ' + eos_token }}{% endif %}{% endfor %}"""
)

TEMPLATES["deepseek_r1"] = (
    """{% if not add_generation_prompt is defined %}{% set add_generation_prompt = false %}{% endif %}{{ bos_token }}{% for message in messages %}{% if message['role'] == 'user' %}{{ '<｜User｜>' + message['content'] }}{% endif %}{% if message['role'] == 'assistant' %}{% set content = message['content'].split('</think>')[-1] %}{{ '<｜Assistant｜>' + content + '<｜end▁of▁sentence｜>' }}{% endif %}{% endfor %}{% if add_generation_prompt %}{{ '<｜Assistant｜>' }}{% endif %}"""
)

TEMPLATES[
    "toolcall_qwen"
] = """{%- macro json_to_python_type(json_spec) %}{{ json_spec.type }}{%- endmacro %}
{%- if tools %}{{- '<|im_start|>system\nYou may call functions.\n<tools>\n' }}{%- for tool in tools %}{{- tool | tojson }}{{- '\n' }}{%- endfor %}{{- '</tools><|im_end|>\n' }}{%- endif %}
{%- for message in messages %}{%- if message.role == "user" %}{{- '<|im_start|>user\n' + message.content + '<|im_end|>\n' }}{%- elif message.role == "assistant" %}{{- '<|im_start|>assistant\n' }}{%- if message.tool_calls %}{%- for tc in message.tool_calls %}{{- '<tool_call>' + (tc.function | tojson) + '</tool_call>' }}{%- endfor %}{%- endif %}{{- '<|im_end|>\n' }}{%- endif %}{%- endfor %}"""

TEMPLATES["command_r"] = (
    """{{ bos_token }}{% if messages[0]['role'] == 'system' %}{% set loop_messages = messages[1:] %}{% set system_message = messages[0]['content'] %}{% else %}{% set loop_messages = messages %}{% set system_message = '## Task and Context\nYou help people answer their questions.' %}{% endif %}{{ '<|START_OF_TURN_TOKEN|><|SYSTEM_TOKEN|>' + system_message + '<|END_OF_TURN_TOKEN|>' }}{% for message in loop_messages %}{% set content = message['content'] %}{{ '<|START_OF_TURN_TOKEN|><|' + message['role'].upper() + '_TOKEN|>' + content | trim + '<|END_OF_TURN_TOKEN|>' }}{% endfor %}"""
)

TEMPLATES["zephyr"] = (
    """{% for message in messages %}\n{% if message['role'] == 'user' %}\n{{ '<|user|>\n' + message['content'] + eos_token }}\n{% elif message['role'] == 'system' %}\n{{ '<|system|>\n' + message['content'] + eos_token }}\n{% elif message['role'] == 'assistant' %}\n{{ '<|assistant|>\n'  + message['content'] + eos_token }}\n{% endif %}\n{% if loop.last and add_generation_prompt %}\n{{ '<|assistant|>' }}\n{% endif %}\n{% endfor %}"""
)

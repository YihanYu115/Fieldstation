"""Independent natural IM/Inbox tools over the existing finite public HTTP API."""
from __future__ import annotations

import json
from copy import deepcopy
from typing import Any
from urllib.parse import quote

from .im_client import IMClient
from .im_contracts import (
    _attach_origin_feedback,
    _check_origin,
    _curate_schema,
    _related_items,
    _review_schema,
)
from .mcp_contract import ContractError, validate
from .packet_contract import PACKET_SCHEMA, FieldInboxError, normalize_packet
from .relation_contract import SCOPED_RELATION_DESCRIPTION, SCOPED_RELATION_TYPES
from .tools_contracts import ToolError, fail

TEXT = {'type': 'string', 'minLength': 1, 'maxLength': 8000}
ID = {'type': 'string', 'minLength': 1, 'maxLength': 512}
ISSUE = {'type': 'string', 'minLength': 1, 'maxLength': 256}
LIMIT = {'type': 'integer', 'minimum': 1, 'maximum': 50, 'default': 20}
VERSION = {'type': 'integer', 'minimum': 0}
BYTES = {'type': 'integer', 'minimum': 256, 'maximum': 16384, 'default': 8192}
PAGE = {'limit': LIMIT, 'cursor': ID, 'expected_snapshot': ID}
PACKET = {'packet_id': ID}


def spec(name, description, properties, required=()):
    return {'name': name, 'description': description, 'inputSchema': {
        'type': 'object', 'properties': properties, 'required': list(required), 'additionalProperties': False}}


def _page_packet_references(packet, args, tool):
    def size(value):
        return len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    names = ('sources', 'attachment_refs', 'original_access')
    offsets = ('source_offset', 'attachment_offset', 'binding_offset')
    if not any(key in args for key in offsets) and size(packet) <= 48_000:
        return packet
    arrays = {name: packet.pop(name, []) for name in names}
    starts = {name: args.get(offset, 0) for name, offset in zip(names, offsets)}
    if any(starts[name] > len(arrays[name]) for name in names):
        fail('invalid_arguments', 'Packet reference offset is beyond its immutable collection')
    for name in names:
        packet[name] = []
    ends = starts.copy()
    for name in names:
        while ends[name] < len(arrays[name]):
            packet[name].append(arrays[name][ends[name]])
            if size(packet) > 45_000:
                packet[name].pop()
                break
            ends[name] += 1
    if ends == starts and any(ends[name] < len(arrays[name]) for name in names):
        fail('response_too_large', 'A packet reference cannot fit within the response budget')
    packet['reference_page'] = {name: {'offset': starts[name], 'total': len(arrays[name])} for name in names}
    if any(ends[name] < len(arrays[name]) for name in names):
        packet['next_read'] = {'tool': tool, 'arguments': {'packet_id': args['packet_id'],
            **({'review_id': args['review_id']} if 'review_id' in args else {}),
            **{offset: ends[name] for name, offset in zip(names, offsets)}}}
    return packet


def definitions():
    submit: dict[str, Any] = deepcopy(PACKET_SCHEMA)
    submit['properties']['issue_id'] = ISSUE
    curate, review = _curate_schema(), _review_schema()
    for item in (curate, review):
        item['inputSchema']['properties']['issue_id'] = ISSUE
        item['description'] = item['description'].replace('已释放', '有权限读取的')
        for value in item['inputSchema']['properties'].values():
            if isinstance(value, dict) and isinstance(value.get('description'), str):
                value['description'] = value['description'].replace('已释放', '有权限读取的')
    # A review's selection is a business judgment, never an automatic whole-packet claim.
    review['inputSchema']['required'].append('handled_fact_refs')
    review['inputSchema']['properties']['handled_fact_refs']['description'] = '本次实际复核的已保存 fact_ref；可为空。不自动推断全文已阅。'
    related = {'type': 'array', 'maxItems': 8, 'items': {
        'type': 'object', 'properties': {'provider_evidence_id': ID,
            'relation_type': {'type': 'string', 'enum': list(SCOPED_RELATION_TYPES)}, 'rationale': TEXT},
        'required': ['provider_evidence_id', 'relation_type', 'rationale'], 'additionalProperties': False}}
    endpoint = {'type': 'object', 'properties': {'part_index': {'type': 'integer', 'minimum': 0, 'maximum': 15},
                                                  'evidence_id': ID},
                'oneOf': [{'required': ['part_index']}, {'required': ['evidence_id']}], 'additionalProperties': False}
    split_parts = {'type': 'array', 'minItems': 2, 'maxItems': 16, 'items': {'type': 'object',
        'properties': {'issue_id': ISSUE, 'kind': {'type': 'string', 'enum': ['observation', 'interpretation']},
                       'text': TEXT}, 'required': ['issue_id', 'kind', 'text'], 'additionalProperties': False}}
    split_decisions = {'type': 'array', 'maxItems': 16, 'items': {'type': 'object',
        'properties': {'relation_id': ID, 'action': {'type': 'string', 'enum': ['withdraw', 'replace']},
                       'part_index': {'type': ['integer', 'null'], 'minimum': 0, 'maximum': 15}, 'reason': TEXT},
        'required': ['relation_id', 'action', 'part_index', 'reason'], 'additionalProperties': False}}
    split_relations = {'type': 'array', 'maxItems': 16, 'items': {'type': 'object',
        'properties': {'issue_id': ISSUE, 'source': endpoint, 'target': endpoint,
                       'relation_type': {'type': 'string', 'enum': list(SCOPED_RELATION_TYPES)}, 'rationale': TEXT},
        'required': ['issue_id', 'source', 'target', 'relation_type', 'rationale'], 'additionalProperties': False}}
    items = [
        {'name': 'submit_field_packet', 'description': '保存实际工作、输入、方法、条件、结果、失败及未决点；尽量区分不同发现及其来源和条件，以便独立质疑和整理，无需预先拆成 Evidence。原件由项目保存。需要保留的工作区成果应按项目原件契约取得可供后续读取的引用；共享工作区可用于临时工作，路径本身不保证留档或版本。缺少能力时如实记录缺口，不阻止保存材料。每次调用是一份新材料。received 仅表示收件，不表示认可或完成。无需任务或运行。', 'inputSchema': submit},
        spec('list_field_packets', '按 Issue 分页读真实 IM 材料索引；沿 next_read 继续。无需 Queue 放行。',
             {'issue_id': ISSUE, 'limit': LIMIT, 'after_packet_id': ID}),
        spec('read_field_packet', '读材料摘要和原文/来源入口；引用较多时沿 next_read 读取全部引用，全文通过 read_field_source 分页。',
             {**PACKET, 'source_offset': VERSION, 'attachment_offset': VERSION, 'binding_offset': VERSION}, ('packet_id',)),
        spec('get_field_summary', '读权威整理版本、映射计数和实际 review 摘要；引用较多时沿 next_read 读取。',
             {**PACKET, 'review_id': ID, 'source_offset': VERSION, 'attachment_offset': VERSION, 'binding_offset': VERSION}, ('packet_id',)),
        spec('read_field_source', '读原文页。start 为 Unicode 码点；沿 next_read 继续。外部附件不在此读取。',
             {**PACKET, 'source_index': VERSION, 'start': VERSION, 'max_bytes': BYTES, 'content_sha256': ID}, ('packet_id',)),
        spec('locate_field_excerpt', '定位逐字摘录；重复引文由参与者选准确位置。',
             {**PACKET, 'source_index': VERSION, 'quoted_text': {**TEXT, 'maxLength': 4000},
              'after_start': VERSION, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 8}}, ('packet_id', 'quoted_text')),
        curate,
        spec('list_curated_field_items', '分页读真实 fact/Evidence 映射；中断后从这些结果继续。',
             {**PACKET, 'limit': LIMIT, 'max_bytes': BYTES, 'after_fact_ref': ID,
              'expected_curation_version': VERSION}, ('packet_id',)),
        spec('read_field_fact', '读 fact、来源锚点和当前真实映射。关系可用 read_evidence_neighbors 展开。',
             {**PACKET, 'fact_ref': ID}, ('packet_id', 'fact_ref')),
        review,
        spec('list_field_reviews', '分页读真实不可变 review 历史，不自动生成复核记录。',
             {**PACKET, 'limit': LIMIT, 'before_version': {'type': 'integer', 'minimum': 1},
              'expected_curation_version': VERSION}, ('packet_id',)),
        spec('read_field_review', '分页读不可变 review 原文；沿 next_read 继续。',
             {**PACKET, 'review_id': ID, 'after_handled': VERSION, 'after_unresolved': VERSION,
              'max_bytes': BYTES, 'expected_curation_version': VERSION}, ('packet_id', 'review_id')),
        spec('create_issue', '创建根 Issue 或指定父 Issue 下的子 Issue；IM 检查 issue.write 和类型规则。每次调用是新动作，未知结果使用 recover_delivery。',
             {'issue_id': {**ISSUE, 'description': '新 Issue 的唯一 ID，使用字母、数字、点、下划线或连字符。'},
              'issue_type': {**ID, 'description': '实际 Issue 类型名称。'},
              'title': {**TEXT, 'description': '问题标题。'},
              'parent_issue_id': {**ISSUE, 'description': '子 Issue 的父 Issue ID；创建根 Issue 时省略。'},
              'scope': {'type': 'object', 'description': '可选的领域范围信息。'},
              'issue_type_registration_id': {**ID, 'description': '可选：明确固定的类型注册 ID。'},
              'reason': {**TEXT, 'description': '可选：创建理由。'}}, ('issue_id', 'issue_type', 'title')),
        spec('inspect_issue', '读 Issue 当前结论、依据、父 Issue 和变化；服务检查实际读取权限。', {'issue_id': ISSUE}),
        spec('list_issue_types', '分页列出可创建的 Issue 类型及其默认结论字段规则。', PAGE),
        spec('read_conclusion_rule', '读取 Issue 当前或指定历史版本的结构化结论规则。',
             {'issue_id': ISSUE, 'revision': VERSION}),
        spec('list_conclusion_history', '分页读取结论历史及各版本提交时的规则版本。', {'issue_id': ISSUE, **PAGE}),
        spec('set_conclusion_rule', '为 Issue 设置后续结论使用的完整规则；旧结论保持原规则。',
             {'issue_id': ISSUE, 'schema': {'type': 'object', 'additionalProperties': True}, 'reason': TEXT},
             ('schema', 'reason')),
        spec('list_child_issues', '分页列直接子 Issue。', {'issue_id': ISSUE, **PAGE}),
        spec('list_issue_evidence', '分页列已登记 Evidence；正文用 read_evidence。', {'issue_id': ISSUE, **PAGE}),
        spec('read_evidence', '读当前 Evidence 正文、版本、来源；不证明核验了外部原件。verification_level=declared 表示声明层级，不代表已核验或错误；quality_status=unknown 表示质量未知，不等于无效或必须先经整理员审核。结合实际依据、关系及规则判断并保留限制。', {'evidence_id': ID}, ('evidence_id',)),
        spec('read_evidence_neighbors', '分页读双向普通/scoped 关系及版本，保留层的区别。', {'evidence_id': ID, **PAGE}, ('evidence_id',)),
        spec('read_split_origins', '分页查看拆分来源、子项或实际 packet/fact 映射；来源声明不证明原件已核验。',
             {'evidence_id': ID, **PAGE, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 8, 'default': 8}}, ('evidence_id',)),
        spec('split_evidence', '按实际内容拆分已有 Evidence；原项保留。指定需撤回或替换的关系，其他关系保持原状；必要关系由参与者明确选择。子项按 parts 的零基位置引用。',
             {'source_evidence_id': ID, 'parts': split_parts, 'relation_decisions': split_decisions,
              'new_relations': split_relations}, ('source_evidence_id', 'parts')),
        spec('discover_original_access', '发现项目登记的原件读取说明和历史版本；说明不授予执行权限。',
             {'issue_id': ISSUE, 'reference': {**ID, 'maxLength': 4096}, 'contract_id': ID, **PAGE}),
        spec('read_original_access', '按 Evidence 的固定原件绑定，或明确 contract_id/revision 读取原件说明。',
             {'issue_id': ISSUE, 'evidence_id': ID, 'reference': {**ID, 'maxLength': 4096}, 'contract_id': ID,
              'revision': {'type': 'integer', 'minimum': 1},
              'max_bytes': {'type': 'integer', 'minimum': 1024, 'maximum': 65536}}),
        spec('save_contribution', '保存带真实来源的观察/解释及必要 scoped 关系。需要留档的工作区成果应按项目原件契约取得可供后续读取的引用；工作区路径本身不保证留档或版本。缺少能力时如实记录缺口，不用输入引用冒充成果。关系须使用实际返回的 Evidence ID，可先浏览 Issue Evidence。每次调用是新贡献；服务端原子检查来源和关系。',
             {'issue_id': ISSUE, 'kind': {'type': 'string', 'enum': ['observation', 'interpretation']},
              'source': ID, 'text': TEXT, 'reason': TEXT, 'related_evidence': related}, ('kind', 'source', 'text', 'reason')),
        spec('create_relation', '保存参与者选择的 scoped 关系；程序固定两端原版本 token，冲突不强交。',
             {'issue_id': ISSUE, 'source_evidence_id': ID, 'target_evidence_id': ID,
              'relation_type': {'type': 'string', 'enum': list(SCOPED_RELATION_TYPES)}, 'rationale': TEXT},
             ('source_evidence_id', 'target_evidence_id', 'relation_type', 'rationale')),
        spec('withdraw_relation', '撤回关系并保留历史；程序固定原版本，恢复不刷新版本。', {'relation_id': ID, 'reason': TEXT}, ('relation_id', 'reason')),
        spec('restore_relation', '恢复关系并保留历史；程序固定原版本。', {'relation_id': ID, 'reason': TEXT}, ('relation_id', 'reason')),
        spec('save_working_conclusion', '按参与者明确选择的依据根保存工作结论，说明适用范围和缺口；declared 或质量 unknown 本身不等于无效或必须先经整理员审核。实际依据资格及适用规则仍由 IM 检查；程序固定原结论头、冻结包和视图，不自动选择科学依据。',
             {'issue_id': ISSUE, 'statement': TEXT, 'evidence_ids': {'type': 'array', 'minItems': 1,
                'maxItems': 16, 'uniqueItems': True, 'items': ID}, 'reason': TEXT,
              'confidence': {'type': 'string', 'enum': ['low', 'medium', 'high']},
              'applicability': TEXT, 'limitations': {'type': 'array', 'maxItems': 16, 'items': TEXT},
              'structured_outputs': {'type': 'object', 'additionalProperties': True}},
             ('statement', 'evidence_ids', 'reason', 'confidence')),
        spec('get_delivery_status', '查询本宿主 journal 的原意图及历史回执；不验证当前领域状态。', {'delivery_id': ID}, ('delivery_id',)),
        spec('recover_delivery', '只重放原意图、目标、正文、授权绑定和 HTTP 身份；不能改内容。', {'delivery_id': ID}, ('delivery_id',)),
    ]
    # A field definition may be reused by several tools or several properties of
    # one tool. Copy each property separately before attaching descriptions;
    # copying the whole schema would preserve aliases inside the copied object.
    for item in items:
        properties = item['inputSchema']['properties']
        item['inputSchema']['properties'] = {name: deepcopy(value) for name, value in properties.items()}
    by_name = {item['name']: item for item in items}
    by_name['read_original_access']['inputSchema']['oneOf'] = [
        {'required': ['evidence_id'], 'not': {'anyOf': [{'required': ['contract_id']}, {'required': ['revision']}]}},
        {'required': ['contract_id', 'revision'], 'not': {'anyOf': [{'required': ['evidence_id']}, {'required': ['reference']}]}},
    ]
    descriptions = {
        'read_field_source': {'source_index': '来源数组的零基下标；省略时读 packet 正文。', 'start': '原文中的零基 Unicode 码点位置；续页优先使用 next_read。', 'content_sha256': '续页时使用上一页返回的原文哈希，防止内容变化。'},
        'locate_field_excerpt': {'quoted_text': 'Exact, unmodified source text; select the real position when repeated.'},
        'discover_original_access': {'issue_id': '原件说明所属项目的 Issue；省略时使用默认 Issue。', 'reference': '可选：按准确原件引用查找适用的说明。', 'contract_id': '可选：只查询该契约家族的历史版本。', 'cursor': '续页游标；保持原查询条件。', 'expected_snapshot': '续页时使用原查询返回的快照。'},
        'read_original_access': {'issue_id': '原件绑定所属项目的 Issue；省略时使用默认 Issue。', 'evidence_id': '使用 Evidence 的冻结原件绑定；可用 reference 选择其中一项。', 'reference': 'Evidence 模式下可选：按真实原件引用选择绑定。', 'contract_id': '明确合同模式：与 revision 同时填写，不填 evidence_id。', 'revision': '明确合同模式：填写所选合同的准确历史版本。'},
        'save_contribution': {'issue_id': '本次贡献的实际目标 Issue；省略时使用默认 Issue。', 'kind': '观察选 observation；解释或判断选 interpretation。', 'source': '本次贡献的一条真实来源定位。原件引用应只填写可直接用于原件工具的准确引用，不要附加哈希、校验结果或其他说明；这些信息可写入 text。不要拼接多个原件引用；需要多个来源时，可分别保存来源贡献并用 related_evidence 表达必要关系。', 'text': '本次观察或解释的内容，保留理解所需的条件和限制；可在这里说明来源的哈希和校验结果。', 'reason': '说明保存该贡献的实际理由。', 'related_evidence': '选择实际工具返回的 Evidence ID、关系类型和理由；可用 list_issue_evidence 查找，勿自行编造 ID。方向为本贡献指向所选目标。'},
        'create_relation': {'source_evidence_id': '所选关系的起点 Evidence ID。', 'target_evidence_id': '所选关系的目标 Evidence ID；关系方向为起点指向目标。', 'rationale': '根据实际证据说明选择该关系的理由。'},
        'save_working_conclusion': {'statement': '当前工作结论的真实表述。', 'evidence_ids': '由参与者明确选择、支撑该结论的实际 Evidence ID。', 'reason': '说明依据及形成该结论的理由。', 'confidence': '参与者判断的信心：low、medium 或 high。', 'applicability': '可选：结论适用的对象与范围。', 'limitations': '可选：已知限制或不确定性。', 'structured_outputs': '按 inspect_issue 返回的 conclusion_rule.schema 填写；必填字段由当前规则决定。'},
    }
    for name, fields in descriptions.items():
        for field, description in fields.items():
            by_name[name]['inputSchema']['properties'][field]['description'] = description
    related = by_name['save_contribution']['inputSchema']['properties']['related_evidence']
    related['items']['properties']['provider_evidence_id']['description'] = 'Actual Evidence ID at the target end of the relation from this new contribution.'
    related['items']['properties']['relation_type']['description'] = SCOPED_RELATION_DESCRIPTION
    by_name['create_relation']['inputSchema']['properties']['relation_type']['description'] = '关系方向为 source → target；depends_on 是必要前提，derived_from 是来源，supports、challenges 和 refutes 表达不同判断。'
    return {item['name']: item for item in items}


SPECS = definitions()


class IMTools:
    def __init__(self, client: IMClient, profile: dict[str, Any]):
        self.client, self.profile = client, profile

    def definitions(self):
        result = []
        for name in self.profile['tools']:
            item = deepcopy(SPECS[name])
            if name in {'submit_field_packet', 'save_contribution'}:
                if 'discover_original_access' in self.profile['tools']:
                    item['description'] += ' 可用 discover_original_access 按目标 Issue 发现项目契约。'
                else:
                    item['description'] += ' 若本会话缺少契约查询能力，可向可信宿主说明缺口。'
            if 'issue_id' in item['inputSchema']['properties'] and not self.profile.get('default_issue_id') and name not in {'curate_field_item', 'record_field_review', 'create_issue'}:
                item['inputSchema']['required'].append('issue_id')
            result.append(item)
        return result

    def call(self, name, arguments):
        if name not in self.profile['tools']:
            fail('tool_not_enabled', 'tool is not enabled in this IM profile')
        if name == 'read_original_access' and isinstance(arguments, dict):
            evidence = 'evidence_id' in arguments
            contract = 'contract_id' in arguments
            revision = 'revision' in arguments
            if (evidence and (contract or revision)) or (not evidence and (not contract or not revision or 'reference' in arguments)):
                issues: list[dict[str, str]] = []
                if evidence:
                    issues.extend({'path': '/' + key, 'rule': 'incompatible_with_evidence_id'}
                                  for key in ('contract_id', 'revision') if key in arguments)
                else:
                    issues.extend({'path': '/' + key, 'rule': 'required'}
                                  for key in ('contract_id', 'revision') if key not in arguments)
                    if 'reference' in arguments:
                        issues.append({'path': '/reference', 'rule': 'requires_evidence_id'})
                raise ContractError('invalid_arguments', 'Use evidence_id with optional reference, or contract_id with revision.',
                                    fields=issues)
        if name == 'submit_field_packet':
            if not isinstance(arguments, dict):
                fail('invalid_input', 'arguments must be an object')
            target = arguments.get('issue_id', self.profile.get('default_issue_id'))
            if not isinstance(target, str) or not target.strip():
                fail('invalid_input', 'issue_id is required when no default is configured')
            normalize_packet(target, {k: v for k, v in arguments.items() if k != 'issue_id'})
        else:
            validate(self.definitions(), name, arguments)
        args = dict(arguments)
        if 'issue_id' in SPECS[name]['inputSchema']['properties'] and name not in {'curate_field_item', 'record_field_review', 'create_issue'}:
            args.setdefault('issue_id', self.profile.get('default_issue_id'))
        try:
            return self._call(name, args)
        except FieldInboxError:
            raise
        except (KeyError, TypeError) as exc:
            if name in {'submit_field_packet', 'curate_field_item', 'record_field_review',
                        'save_contribution', 'create_relation', 'withdraw_relation', 'restore_relation',
                        'save_working_conclusion', 'recover_delivery', 'create_issue', 'set_conclusion_rule', 'split_evidence'}:
                raise ToolError('invalid_response', 'IM response cannot be interpreted; recover original delivery', effect='unknown') from exc
            raise ToolError('invalid_response', 'IM read response cannot be interpreted; retry the same read') from exc

    def _write(self, name, path, body, continuation=None):
        delivery_id = self.client.begin(name, path, body, continuation=continuation)
        try:
            return self.client.recover(delivery_id)
        except ToolError as exc:
            if exc.operation_id is None:
                exc.operation_id = delivery_id
            raise
        except Exception as exc:
            raise ToolError('tool_error', 'Recover the original delivery', effect='unknown',
                            operation_id=delivery_id) from exc

    def _remember_split_observation(self, identity, result):
        observed = result.pop('split_observation')
        if not (isinstance(observed, str) and observed or observed == {
                'status': 'unavailable', 'code': 'split_boundary_too_large'}):
            raise ToolError('invalid_response', 'IM returned an invalid split observation')
        with self.client.journal.lock():
            value = self.client.journal.load()
            value.setdefault('split_observations', {})[identity] = observed
            relations = value.setdefault('split_relation_observations', {})
            for item in result.get('items', []):
                if (item.get('layer') == 'scoped-v2' and not item.get('restricted')
                        and isinstance(item.get('relation_id'), str) and isinstance(item.get('version_id'), str)):
                    relations[item['relation_id']] = item['version_id']
            self.client.journal.save(value)
        if isinstance(observed, dict):
            result['split_observation_notice'] = {'code': 'split_boundary_too_large',
                'message': 'Reading succeeded; splitting requires a bounded observation and a fresh read.'}
        return result

    def _split_snapshot(self, identity):
        with self.client.journal.lock():
            observed = self.client.journal.load().get('split_observations', {}).get(identity)
        if isinstance(observed, dict):
            raise ToolError('split_boundary_too_large',
                            'The observed split boundary was too large; obtain a bounded fresh observation before splitting',
                            status=409)
        if observed:
            return observed
        return self.client._request('GET', '/v1/direct-evidence-splits/boundary/' +
                                    quote(identity, safe=''))['snapshot']

    def _call(self, name, args):
        client = self.client
        issue = args.pop('issue_id', None)
        if name == 'read_split_origins':
            from urllib.parse import urlencode
            identity = args.pop('evidence_id')
            route = '/v1/direct-evidence-splits/origins/' + quote(identity, safe='')
            if args:
                route += '?' + urlencode(args)
            result = client._request('GET', route)
            cursor, snapshot = result.get('next_cursor'), result.get('snapshot')
            result['next_read'] = ({'tool': name, 'arguments': {'evidence_id': identity, **args, 'cursor': cursor,
                                    'expected_snapshot': snapshot}} if cursor and snapshot else None)
            return result
        if name == 'split_evidence':
            source = args['source_evidence_id']
            boundary = self._split_snapshot(source)
            args.setdefault('relation_decisions', [])
            args.setdefault('new_relations', [])
            identities = {endpoint['evidence_id'] for edge in args['new_relations']
                          for endpoint in (edge['source'], edge['target']) if 'evidence_id' in endpoint}
            snapshots = {identity: self._split_snapshot(identity) for identity in sorted(identities)}
            with client.journal.lock():
                observed_relations = client.journal.load().get('split_relation_observations', {})
                versions = {item['relation_id']: observed_relations[item['relation_id']]
                            for item in args['relation_decisions'] if item['relation_id'] in observed_relations}
            body = {**args, 'expected_snapshot': boundary, 'extra_snapshots': snapshots,
                    'observed_relation_versions': versions}
            return self._write(name, '/v1/direct-evidence-splits', body)
        if name == 'create_issue':
            return self._write(name, '/v1/issues', {'issue_id': issue, **args})
        if name == 'list_issue_types':
            result = client.list_issue_types(**args)
            cursor, snapshot = result.get('next_cursor'), result.get('snapshot')
            result['next_read'] = ({'tool': name, 'arguments': {**args, 'cursor': cursor,
                                    'expected_snapshot': snapshot}} if cursor and snapshot else None)
            return result
        if name == 'read_conclusion_rule':
            path = '/v1/conclusion-rules/issue/' + quote(issue, safe='')
            if 'revision' in args:
                path += '?revision=' + str(args['revision'])
            return client._request('GET', path)
        if name == 'set_conclusion_rule':
            path = '/v1/conclusion-rules/issue/' + quote(issue, safe='')
            current = client._request('GET', path)
            return self._write(name, path, {**args, 'expected_revision': current['revision']})
        if name == 'get_delivery_status':
            return client.status(args['delivery_id'])
        if name == 'recover_delivery':
            delivery_id = args['delivery_id']
            try:
                return client.recover(delivery_id)
            except ToolError as exc:
                if exc.operation_id is None:
                    exc.operation_id = delivery_id
                raise
            except Exception as exc:
                raise ToolError('tool_error', 'Recover the original delivery', effect='unknown',
                                operation_id=delivery_id) from exc
        if name == 'submit_field_packet':
            return self._write(name, '/v1/field-packets', normalize_packet(issue, args))
        if name == 'list_field_packets':
            result = client.list_field_packets(issue, **args)
            for item in result['items']:
                item['read'] = {'tool': 'read_field_packet', 'arguments': {'packet_id': item['packet_id']}}
            if result.get('next_cursor'):
                result['next_read'] = {'tool': name, 'arguments': {**args, 'issue_id': issue,
                    'after_packet_id': result['next_cursor']}}
            return result
        if name in {'curate_field_item', 'record_field_review'}:
            packet_id = args.pop('packet_id')
            packet = client.field_packet(packet_id)
            if issue is not None and issue != packet['issue_id']:
                fail('scope_mismatch', 'explicit/default Issue does not match the actual packet; choose its Issue')
            body = {'issue_id': packet['issue_id'], 'expected_curation_version': packet['curation_version'], **args}
            if name == 'curate_field_item':
                try:
                    _check_origin(packet, args['origin'])
                except FieldInboxError as exc:
                    _attach_origin_feedback(exc, packet, args['origin'], packet_id, '/origin')
                    raise
                body['related_evidence'] = _related_items(args.get('related_evidence', []))
                path = '/curated-items'
            else:
                body.setdefault('unresolved', [])
                for index, item in enumerate(body['unresolved']):
                    _check_origin(packet, item['origin'], path=f'/unresolved/{index}/origin')
                path = '/reviews'
            return self._write(name, '/v1/field-packets/' + quote(packet_id, safe='') + path, body)
        if name == 'read_field_packet':
            packet = client.field_packet(args['packet_id'])
            packet['content_preview'] = packet.pop('content')[:500]
            packet['content_read'] = {'tool': 'read_field_source', 'arguments': {'packet_id': args['packet_id']}}
            for index, source in enumerate(packet['sources']):
                source.pop('provided_text', None)
                source['read'] = {'tool': 'read_field_source', 'arguments': {'packet_id': args['packet_id'], 'source_index': index}}
            if 'list_curated_field_items' in self.profile['tools'] and packet.get('packet_id'):
                packet['curated_read'] = {'tool': 'list_curated_field_items', 'arguments': {'packet_id': packet['packet_id']}}
            return _page_packet_references(packet, args, name)
        if name == 'get_field_summary':
            summary_args = {key: value for key, value in args.items() if key not in ('source_offset', 'attachment_offset', 'binding_offset')}
            return _page_packet_references(client.field_packet_summary(**summary_args), args, name)
        if name == 'read_field_source':
            result = client.field_source(**args)
            if result.get('next_cursor') is not None:
                result['next_read'] = {'tool': name, 'arguments': {**args, 'start': result['next_cursor'],
                    'content_sha256': result['content_sha256']}}
            return result
        if name == 'locate_field_excerpt':
            return client.locate_field_excerpt(**args)
        if name in {'list_curated_field_items', 'list_field_reviews'}:
            packet = client.field_packet_summary(args['packet_id'])
            args.setdefault('expected_curation_version', packet['curation_version'])
            result = (client.curated_field_items(**args) if name == 'list_curated_field_items'
                      else client.field_reviews(**args))
            if result.get('next_cursor') is not None:
                cursor = 'after_fact_ref' if name == 'list_curated_field_items' else 'before_version'
                result['next_read'] = {'tool': name, 'arguments': {**args, cursor: result['next_cursor']}}
            return result
        if name == 'read_field_fact':
            return client.field_packet_fact(**args)
        if name == 'read_field_review':
            result = client.field_review(**args)
            if result.get('handled_next_cursor') is not None or result.get('unresolved_next_cursor') is not None:
                result['next_read'] = {'tool': name, 'arguments': {**args,
                    'after_handled': result.get('handled_next_cursor') or result['handled_count'],
                    'after_unresolved': result.get('unresolved_next_cursor') or result['unresolved_count'],
                    'expected_curation_version': result['curation_version']}}
            return result
        if name == 'inspect_issue':
            result = client.browse_issue(issue)
            actual = result.get('issue', {})
            if isinstance(actual, dict):
                actual_id, parent = actual.get('issue_id'), actual.get('parent_issue_id')
                if isinstance(parent, str) and parent and 'inspect_issue' in self.profile['tools']:
                    result['parent_read'] = {'tool': 'inspect_issue', 'arguments': {'issue_id': parent}}
                if isinstance(actual_id, str) and actual_id:
                    for tool, key in [('list_child_issues', 'children_read'), ('list_issue_evidence', 'evidence_read')]:
                        if tool in self.profile['tools']:
                            result[key] = {'tool': tool, 'arguments': {'issue_id': actual_id}}
            return result
        if name in {'list_child_issues', 'list_issue_evidence', 'list_conclusion_history', 'read_evidence_neighbors', 'discover_original_access'}:
            if name == 'list_child_issues':
                result = client.browse_children(issue, **args)
            elif name == 'list_issue_evidence':
                result = client.browse_evidence(issue, **args)
            elif name == 'list_conclusion_history':
                result = client.browse_conclusions(issue, **args)
            elif name == 'read_evidence_neighbors':
                options: dict[str, Any] = {'split_observation': 1} if 'split_evidence' in self.profile['tools'] else {}
                result = client.browse_neighbors(**args, **options)
                if options:
                    self._remember_split_observation(args['evidence_id'], result)
            else:
                result = client.discover_original_access(issue, **args)
            for item in result.get('items', []):
                if not isinstance(item, dict) or item.get('restricted'):
                    continue
                if name == 'list_child_issues' and 'inspect_issue' in self.profile['tools']:
                    if isinstance(item.get('issue_id'), str) and item['issue_id']:
                        item['read'] = {'tool': 'inspect_issue', 'arguments': {'issue_id': item['issue_id']}}
                if name == 'list_issue_evidence' and 'read_evidence' in self.profile['tools']:
                    if isinstance(item.get('evidence_id'), str) and item['evidence_id']:
                        item['read'] = {'tool': 'read_evidence', 'arguments': {'evidence_id': item['evidence_id']}}
                if name == 'read_evidence_neighbors' and 'read_evidence' in self.profile['tools']:
                    for side in ('source', 'target'):
                        evidence_id = item.get(side + '_evidence_id')
                        if isinstance(evidence_id, str) and evidence_id:
                            item[side + '_read'] = {'tool': 'read_evidence', 'arguments': {'evidence_id': evidence_id}}
            cursor, snapshot = result.get('next_cursor'), result.get('snapshot')
            if cursor is not None and isinstance(snapshot, str) and snapshot:
                continuation = {**args, 'cursor': cursor, 'expected_snapshot': snapshot}
                continuation.setdefault('limit', 20)
                if name != 'read_evidence_neighbors':
                    continuation['issue_id'] = issue
                result['next_read'] = {'tool': name, 'arguments': continuation}
            else:
                result['next_read'] = None
            return result
        if name == 'read_evidence':
            options = {'split_observation': 1} if 'split_evidence' in self.profile['tools'] else {}
            result = client.browse_evidence_detail(args['evidence_id'], **options)
            return self._remember_split_observation(args['evidence_id'], result) if options else result
        if name == 'read_original_access':
            return client.read_original_access(issue, **args)
        if name == 'save_contribution':
            body = {'issue_id': issue, **args, 'description': args.pop('text')}
            body.pop('text', None)
            body.setdefault('related_evidence', [])
            return self._write(name, '/v1/scoped-evidence-contributions', body)
        if name == 'create_relation':
            source = client.scoped_relation_binding(args['source_evidence_id'])
            target = client.scoped_relation_binding(args['target_evidence_id'])
            body = {'scope_issue_id': issue, **args, 'expected_source_token': source['token'],
                    'expected_target_token': target['token']}
            return self._write(name, '/v1/scoped-evidence-relations', body)
        if name in {'withdraw_relation', 'restore_relation'}:
            relation = client.scoped_relation(args['relation_id'])
            body = {'expected_version_id': relation['version_id'], 'reason': args['reason']}
            action = 'deactivate' if name == 'withdraw_relation' else 'reactivate'
            return self._write(name, '/v1/scoped-evidence-relations/' + quote(args['relation_id'], safe='') + '/' + action, body)
        if name == 'save_working_conclusion':
            inspected = client.inspect_issue(issue)
            head = inspected['issue']
            roots = args.pop('evidence_ids')
            body = {'issue_id': issue, **args, 'expected_current_conclusion_id': head.get('current_conclusion_id'),
                    'expected_conclusion_revision': head['conclusion_revision'],
                    'expected_rule_revision': inspected['conclusion_rule']['revision']}
            return self._write(name, '/v1/currentness/prepare', {'issue_id': issue, 'evidence_ids': roots},
                               {'evidence_ids': roots, 'body': body})
        raise ContractError('tool_not_available', 'unknown IM tool')

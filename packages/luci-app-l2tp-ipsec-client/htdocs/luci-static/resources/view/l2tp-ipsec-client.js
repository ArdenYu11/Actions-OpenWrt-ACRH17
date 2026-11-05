'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require ui';
'require uci';

var statusRPC = rpc.declare({ object: 'l2tp-ipsec-client', method: 'status', expect: {} });
var logsRPC = rpc.declare({ object: 'l2tp-ipsec-client', method: 'logs', expect: {} });
var validateRPC = rpc.declare({ object: 'l2tp-ipsec-client', method: 'validate', expect: {} });
var startRPC = rpc.declare({ object: 'l2tp-ipsec-client', method: 'start', expect: {} });
var stopRPC = rpc.declare({ object: 'l2tp-ipsec-client', method: 'stop', expect: {} });

var phases = {
 disconnected: '未连接', resolving: '解析服务器', ipsec: '建立 IPsec',
 ppp: '连接 PPP', connected: '已连接', retrying: '等待重连',
 conflict: '进程冲突', error: '连接失败'
};

function validText(value, required) {
 if (!value) return required ? '请填写此项。' : true;
 return /[\x00-\x1f\x7f]/.test(value) ? '不能包含换行或控制字符。' : true;
}

function ipv4(value) {
 var parts = value.split('.');
 return parts.length === 4 && parts.every(function(p) {
  return /^\d{1,3}$/.test(p) && Number(p) <= 255;
 });
}

function domain(value, prefix) {
 if (!value) return true;
 if (prefix) value = value.replace(/\.$/, '');
 return value.length <= 253 && value.split('.').every(function(label) {
  return label.length >= 1 && label.length <= 63 && /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/.test(label);
 }) ? true : '请填写域名文本，不包含协议、端口、路径或通配符。';
}

var ruleTypes = {
 subnet: { key: 'routes', title: '指定网段', placeholder: '10.20.0.0/16', help: '填写 IPv4 CIDR 网段，例如 10.20.0.0/16。' },
 exact: { key: 'domains', title: '完整域名', placeholder: 'api.example.com', help: '只匹配这个完整域名，不包括它的子域。' },
 prefix: { key: 'domain_prefixes', title: '域名前缀', placeholder: 'internal-', help: '匹配域名开头，例如 api. 或 internal-。' },
 suffix: { key: 'domain_suffixes', title: '域名后缀', placeholder: 'example.com', help: '匹配本域及全部子域，不匹配 badexample.com。' }
};

function probeTarget(value) {
 if (!value) return true;
 if (ipv4(value)) return true;
 if (/^[0-9.]+$/.test(value)) return '请填写有效的 IPv4 地址或域名。';
 return domain(value, false);
}

function validateRule(type, value) {
 if (!ruleTypes[type]) return '请选择规则类型。';
 if (!value) return '请填写规则内容。';
 if (type !== 'subnet') return domain(value, type === 'prefix');
 var parts = value.split('/');
 return parts.length === 2 && ipv4(parts[0]) && /^\d{1,2}$/.test(parts[1]) &&
  Number(parts[1]) >= 1 && Number(parts[1]) <= 32 ? true : '请填写 IPv4 CIDR 网段，例如 10.20.0.0/16。';
}

function readRules(get) {
 var entries = [];
 Object.keys(ruleTypes).forEach(function(type) {
  var values = get(ruleTypes[type].key);
  (Array.isArray(values) ? values : values ? [values] : []).forEach(function(value) {
   entries.push({ type: type, value: value });
  });
 });
 return entries;
}

function groupRules(entries) {
 var grouped = {};
 Object.keys(ruleTypes).forEach(function(type) { grouped[ruleTypes[type].key] = []; });
 entries.forEach(function(entry) { grouped[ruleTypes[entry.type].key].push(entry.value); });
 return grouped;
}

function ruleError(entries, type, value, editing) {
 var error = validateRule(type, value);
 if (error !== true) return error;
 if (entries.some(function(entry, index) {
  return index !== editing && entry.type === type && entry.value.toLowerCase() === value.toLowerCase();
 })) return '这条规则已经存在。';
 var count = entries.filter(function(entry, index) { return index !== editing && entry.type !== 'subnet'; }).length;
 return type !== 'subnet' && count >= 512 ? '域名规则总数不能超过 512 条。' : true;
}

function ruleEditor(entries) {
 var list = E('div', { 'class': 'lp-rule-list' });
 var root = E('div', { 'class': 'lp-rules-editor' }, [list]);
 var paint = function() {
  if (!entries.length) {
   list.replaceChildren(E('div', { 'class': 'lp-rules-empty' }, '尚未添加规则。添加网段或域名，命中任意一条即走 VPN。'));
   return;
  }
  list.replaceChildren.apply(list, entries.map(function(entry, index) {
   return E('div', { 'class': 'lp-rule-row' }, [
    E('div', { 'class': 'lp-rule-content' }, [
     E('span', { 'class': 'lp-rule-type' }, ruleTypes[entry.type].title),
     E('span', { 'class': 'lp-rule-value' }, entry.value)
    ]),
    E('div', { 'class': 'lp-rule-actions' }, [
     E('button', { type: 'button', 'class': 'cbi-button', 'aria-label': '编辑规则 ' + entry.value, click: function() { edit(index); } }, '编辑'),
     E('button', { type: 'button', 'class': 'cbi-button lp-rule-delete', 'aria-label': '删除规则 ' + entry.value, click: function() { entries.splice(index, 1); paint(); } }, '删除')
    ])
   ]);
  }));
 };
 var edit = function(index) {
  var entry = index == null ? { type: 'subnet', value: '' } : entries[index];
  var category = E('select', { id: 'lp-rule-category', 'aria-label': '规则类型' }, [
   E('option', { value: 'subnet' }, '指定网段'), E('option', { value: 'domain' }, '域名')
  ]);
  var match = E('select', { id: 'lp-rule-match', 'aria-label': '域名匹配方式' }, ['exact', 'prefix', 'suffix'].map(function(type) {
   return E('option', { value: type }, ruleTypes[type].title);
  }));
  var matchRow = E('div', { 'class': 'lp-modal-field' }, [E('label', { for: 'lp-rule-match' }, '匹配方式'), match]);
  var input = E('input', { id: 'lp-rule-value', type: 'text', 'aria-label': '规则内容', autocomplete: 'off' });
  var help = E('p', { 'class': 'lp-modal-help' });
  var error = E('p', { 'class': 'lp-modal-error', role: 'alert' });
  category.value = entry.type === 'subnet' ? 'subnet' : 'domain';
  match.value = entry.type === 'subnet' ? 'exact' : entry.type;
  input.value = entry.value;
  var type = function() { return category.value === 'subnet' ? 'subnet' : match.value; };
  var update = function() {
   matchRow.hidden = category.value === 'subnet';
   input.placeholder = ruleTypes[type()].placeholder;
   help.textContent = ruleTypes[type()].help;
   error.textContent = '';
  };
  category.addEventListener('change', update); match.addEventListener('change', update); update();
  var save = function() {
   var value = input.value.trim();
   var message = ruleError(entries, type(), value, index);
   if (message !== true) { error.textContent = message; input.focus(); return; }
   var changed = { type: type(), value: value };
   if (index == null) entries.push(changed); else entries[index] = changed;
   paint(); ui.hideModal();
  };
  input.addEventListener('keydown', function(event) { if (event.key === 'Enter') { event.preventDefault(); save(); } });
  ui.showModal(index == null ? '添加规则' : '编辑规则', [
   E('div', { 'class': 'lp-modal-field' }, [E('label', { for: 'lp-rule-category' }, '规则类型'), category]),
   matchRow,
   E('div', { 'class': 'lp-modal-field' }, [E('label', { for: 'lp-rule-value' }, '规则内容'), input]),
   help, error,
   E('div', { 'class': 'lp-modal-actions' }, [
    E('button', { type: 'button', 'class': 'cbi-button', click: function() { ui.hideModal(); } }, '取消'),
    E('button', { type: 'button', 'class': 'cbi-button cbi-button-positive', click: save }, index == null ? '添加' : '保存修改')
   ])
  ], 'lp-rule-modal');
  input.focus();
 };
 root.appendChild(E('button', { type: 'button', 'class': 'cbi-button lp-add-rule', click: function() { edit(null); } }, '+ 添加规则'));
 paint(); return root;
}

return view.extend({
 load: function() {
  return Promise.all([uci.load('l2tpipsec'), statusRPC(), logsRPC()]);
 },

 render: function(data) {
  var self = this;
  var m = new form.Map('l2tpipsec');
  this.map = m;
  var s = m.section(form.NamedSection, 'main', 'client');
  s.addremove = false;
  s.tab('basic', '连接设置');
  s.tab('routes', '流量路由');
  s.tab('advanced', '高级设置');
  var o;

  o = s.taboption('basic', form.Value, 'server', '服务器地址');
  o.placeholder = 'vpn.example.com'; o.rmempty = false;
  o.validate = function(section, value) {
   return value && value.length <= 253 && /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(value)
    ? true : '请填写 IPv4 地址或域名，不包含协议和端口。';
  };
  o = s.taboption('basic', form.Value, 'username', '用户名');
  o.rmempty = false; o.datatype = 'maxlength(128)';
  o.validate = function(section, value) { return validText(value, true); };
  o = s.taboption('basic', form.Value, 'password', '密码');
  o.password = true; o.rmempty = false; o.datatype = 'maxlength(256)';
  o.validate = function(section, value) { return validText(value, true); };
  o = s.taboption('basic', form.Value, 'psk', '预共享密钥（PSK）');
  o.password = true; o.rmempty = false; o.datatype = 'maxlength(256)';
  o.description = '由 VPN 管理员提供，用于建立 IPsec 加密连接。';
  o.validate = function(section, value) { return validText(value, true); };
  o = s.taboption('basic', form.Flag, 'enabled', '开机自动连接');
  o.default = '0'; o.rmempty = false;
  o.description = '开启后，路由器重启时自动连接。手动断开只影响本次运行。';
  o = s.taboption('basic', form.Flag, 'reconnect', '断线自动重连');
  o.default = '1'; o.rmempty = false;
  o = s.taboption('basic', form.Value, 'retry_max_attempts', '最大重连次数');
  o.default = '0'; o.datatype = 'range(0,10000)'; o.rmempty = false;
  o.depends('reconnect', '1'); o.retain = true;
  o.description = '0 表示不限次数。首次连接不计入；成功连接后重新计数。';
  o = s.taboption('basic', form.Value, 'retry_interval', '最大重连间隔（秒）');
  o.default = '30'; o.datatype = 'range(1,3600)'; o.rmempty = false;
  o.depends('reconnect', '1'); o.retain = true;
  o.description = '间隔按 1、2、3、5、8……秒递增；达到最大间隔后，从 1 秒重新循环。例如最大值为 8：1、2、3、5、8、1、2……。';

  o = s.taboption('routes', form.ListValue, 'routing_mode', '路由模式');
  o.value('full', '全流量');
  o.value('rules', '规则分流');
  o.default = 'rules'; o.rmempty = false;
  o.description = '全流量：IPv4 外网流量走 VPN，保留已有本地路由，阻止 IPv6 外网。规则分流：命中下方任意网段或域名规则即走 VPN，其余使用原有出口。';
  var entries = readRules(function(key) { return uci.get('l2tpipsec', 'main', key); });
  o = s.taboption('routes', form.DummyValue, '_rules', '已添加规则');
  o.depends('routing_mode', 'rules'); o.retain = true;
  o.description = '网段和域名规则同时生效，命中任意一条即走 VPN。添加或编辑规则后，点击下方“保存设置”或“保存并连接”。';
  o.renderWidget = function() { return ruleEditor(entries); };
  o.parse = function(section) {
   var grouped = groupRules(entries);
   Object.keys(grouped).forEach(function(key) {
    if (grouped[key].length) uci.set('l2tpipsec', section, key, grouped[key]);
    else uci.unset('l2tpipsec', section, key);
   });
   return Promise.resolve();
  };

  o = s.taboption('routes', form.Value, 'vpn_dns', 'VPN DNS（可选）');
  o.placeholder = '自动使用 VPN 下发的 DNS'; o.datatype = 'ip4addr';
  o.description = '全流量或使用域名规则时需要可用的 VPN DNS。留空则使用 PPP 下发的地址；未下发时请填写。域名规则要求设备使用路由器 DNS，DoH/DoT 和已有缓存不会触发匹配；共享 IP 的其他域名也可能走 VPN。';
  o = s.taboption('routes', form.Value, 'probe_ip', '内网探测地址（可选）');
  o.placeholder = '10.20.0.10 或 intranet.example.com';
  o.validate = function(section, value) { return probeTarget(value); };
  o.description = '填写允许 Ping 的 IPv4 地址或域名。域名先解析为 IPv4，再检查路由和连通性；规则分流时需命中已添加的网段或域名规则。';

  o = s.taboption('advanced', form.DummyValue, '_protocol', '协议与认证');
  o.cfgvalue = function() { return 'L2TP over IPsec · IKEv1 · Transport · PSK + PAP'; };
  o.description = '适用于使用预共享密钥和 PAP 的 L2TP/IPsec 服务。';
  o = s.taboption('advanced', form.ListValue, 'ike', 'IKE 加密算法');
  ['aes256-sha256-modp2048', 'aes128-sha256-modp2048', 'aes256-sha1-modp2048', 'aes128-sha1-modp2048']
   .forEach(function(v) { o.value(v, v); });
  o.default = 'aes256-sha256-modp2048'; o.rmempty = false;
  o = s.taboption('advanced', form.ListValue, 'esp', 'ESP 加密算法');
  ['aes256-sha1', 'aes128-sha1', 'aes256-sha256', 'aes128-sha256']
   .forEach(function(v) { o.value(v, v); });
  o.default = 'aes256-sha1'; o.rmempty = false;
  ['local_id', 'remote_id'].forEach(function(key) {
   o = s.taboption('advanced', form.Value, key, key === 'local_id' ? '本地身份标识（可选）' : '远端身份标识（可选）');
   o.datatype = 'maxlength(253)';
   o.description = key === 'local_id' ? '默认使用 WAN 出口地址。' : '留空时接受持有正确 PSK 的远端身份。';
   o.validate = function(section, value) { return validText(value, false); };
  });
  [
   ['mtu', 'MTU / MRU', '1400', 'range(576,1460)', ''],
   ['lcp_interval', 'PPP 保活间隔（秒）', '30', 'range(5,300)', ''],
   ['lcp_failure', 'PPP 保活失败次数', '5', 'range(1,20)', '连续失败达到此次数时判定连接中断。']
  ].forEach(function(item) {
   o = s.taboption('advanced', form.Value, item[0], item[1]);
   o.default = item[2]; o.datatype = item[3]; o.rmempty = false; o.description = item[4];
  });

  return m.render().then(function(mapNode) {
   self.statusNode = E('div', { 'class': 'lp-status' });
   self.logNode = E('pre', { 'class': 'lp-log' });
   var action = function(label, style, run) {
    return E('button', { 'class': 'cbi-button ' + style, 'click': ui.createHandlerFn(self, run) }, label);
   };
   self.connectButton = action('保存并连接', 'cbi-button-positive', function() { return self.saveAndRun(startRPC); });
   self.stopButton = action('断开连接', 'cbi-button-negative', function() { return self.runAction(stopRPC); });
   self.saveButton = action('保存设置', 'cbi-button-apply', function() { return self.saveAndRun(null); });
   var node = E('div', { 'class': 'lp-page' }, [
    E('style', {}, `.lp-page select,.lp-rule-modal select{appearance:none;-webkit-appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'%3E%3Cpath d='M3 5l4 4 4-4' fill='none' stroke='%2353667c' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:42px!important}.lp-page .cbi-dropdown>span.open{padding-right:14px;margin-right:4px}.lp-rule-list{border:1px solid #dbe2ea;border-radius:7px;overflow:hidden}.lp-rules-empty{padding:20px;color:#788799;background:#f8fafc;line-height:1.7}.lp-rule-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:13px 15px;border-bottom:1px solid #e8edf3}.lp-rule-row:last-child{border-bottom:0}.lp-rule-content{display:flex;align-items:center;gap:12px;min-width:0;flex-wrap:wrap}.lp-rule-type{font-size:12px;color:#506784;background:#edf3fb;padding:3px 8px;border-radius:4px;white-space:nowrap}.lp-rule-value{overflow-wrap:anywhere}.lp-rule-actions{display:flex;gap:8px;flex-shrink:0}.lp-rule-actions button{font-size:12px;padding:5px 9px}.lp-rule-delete{color:#ae4343}.lp-add-rule{margin-top:12px}.lp-rule-modal [hidden]{display:none!important}.lp-modal-field{display:flex;flex-direction:column;gap:7px;margin:15px 0}.lp-modal-field label{font-weight:500}.lp-modal-field input,.lp-modal-field select{box-sizing:border-box;width:100%;max-width:none;font:inherit;min-height:40px;padding:9px 12px;border:1px solid #cfd8e5;border-radius:5px;background-color:#fff;color:#263548}.lp-modal-help{color:#788799;font-size:13px;line-height:1.7}.lp-modal-error{color:#b91c1c;font-size:13px;min-height:20px}.lp-modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}@media(max-width:600px){.lp-rule-row{align-items:flex-start;gap:10px}.lp-rule-content{gap:7px;flex-direction:column;align-items:flex-start}}.lp-status{padding:18px 20px;border:1px solid #dbe2ea;border-radius:8px;background:#f8fafc;margin:0 0 22px;color:#263548}.lp-status-heading{display:flex;align-items:center;gap:10px;margin-bottom:8px}.lp-badge{font-weight:600;padding:3px 10px;border-radius:20px;background:#e5eaf0;color:#536273}.lp-badge[data-phase="connected"]{background:#dcfce7;color:#166534}.lp-badge[data-phase="error"],.lp-badge[data-phase="conflict"]{background:#fee2e2;color:#991b1b}.lp-steps{display:flex;gap:28px;margin-top:16px;flex-wrap:wrap}.lp-step{font-size:13px;color:#59687b}.lp-step[data-ok="true"]{color:#15803d}.lp-actions{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}.lp-log{white-space:pre-wrap;overflow-wrap:anywhere;background:#152132;color:#d7e3f0;padding:18px;border-radius:8px;min-height:100px;max-height:300px;overflow:auto;font-size:12px;line-height:1.7}.lp-details{color:#69798b;font-size:12px;margin-top:12px}.lp-note{font-size:13px;color:#66778a;margin-top:16px}.lp-page details>summary{cursor:pointer;margin:18px 0 10px;font-weight:600}`),
    E('h2', {}, 'L2TP/IPsec 客户端'),
    E('p', { 'class': 'lp-note' }, '填写连接信息，选择全流量或网段与域名规则分流。'),
    self.statusNode,
    mapNode,
    E('div', { 'class': 'lp-actions' }, [self.connectButton, self.stopButton, self.saveButton]),
    E('details', {}, [E('summary', {}, '连接日志'), self.logNode]),
    E('p', { 'class': 'lp-note' }, '设置保存于路由器本地。密码与 PSK 不会出现在连接日志中。')
   ]);
   self.paint(data[1], data[2]);
   poll.add(function() { return self.refresh(); }, 5);
   return node;
  });
 },

 paint: function(state, logs) {
  var reach = { yes: '可达', no: '未响应', no_route: '缺少路由', unknown: '未检测', resolve_failed: '域名解析失败' };
  var steps = [
   ['IPsec 加密', state.ipsec ? '已建立' : '未建立', !!state.ipsec],
   ['PPP 连接', state.ppp ? '已连接' : '未连接', !!state.ppp],
   ['内网探测', state.probe_ip ? (reach[state.reachable] || '未检测') : '未配置', state.reachable === 'yes']
  ];
  this.statusNode.replaceChildren(
   E('div', { 'class': 'lp-status-heading' }, [E('strong', {}, '连接状态'),
    E('span', { 'class': 'lp-badge', 'data-phase': state.phase }, phases[state.phase] || '未知状态')]),
   E('div', {}, state.message || '尚未连接。'),
   E('div', { 'class': 'lp-steps' }, steps.map(function(step) {
    return E('div', { 'class': 'lp-step', 'data-ok': String(step[2]) }, step[0] + '：' + step[1]);
   })),
   E('div', { 'class': 'lp-details' }, state.address ? 'VPN 地址：' + state.address + ' · 模式：' + (state.routing_mode === 'full' ? '全流量' : '规则分流') + ' · 接口：l2tp-vpn' : '接口：l2tp-vpn'),
   state.probe_address && state.probe_address !== state.probe_ip ? E('div', { 'class': 'lp-details' }, '探测地址：' + state.probe_ip + ' → ' + state.probe_address) : E('span', {})
  );
  this.logNode.textContent = logs.log || '暂无连接日志。';
  this.stopButton.disabled = !state.running;
 },

 refresh: function() {
  var self = this;
  return Promise.all([statusRPC(), logsRPC()]).then(function(data) { self.paint(data[0], data[1]); });
 },

 runAction: function(fn) {
  var self = this;
  return fn().then(function(reply) {
   ui.addNotification(null, E('p', {}, reply.message), reply.ok ? 'info' : 'error');
   return self.refresh();
  });
 },

 saveAndRun: function(fn) {
  var self = this;
  return this.map.save().then(function() { return uci.apply(); })
   .then(function() { return validateRPC(); })
   .then(function(reply) {
    if (!reply.ok) throw new Error(reply.message);
    if (fn) return self.runAction(fn);
    ui.addNotification(null, E('p', {}, '设置已保存。连接参数会在下次连接时生效。'), 'info');
   });
 },

 handleSave: null,
 handleSaveApply: null,
 handleReset: null
});

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

  o = s.taboption('routes', form.ListValue, 'routing_mode', '路由模式');
  o.value('full', '全流量');
  o.value('rules', '规则分流');
  o.default = 'rules'; o.rmempty = false;
  o.description = '全流量：IPv4 外网流量走 VPN，保留已有本地路由，阻止 IPv6 外网。规则分流：命中下方任意网段或域名规则即走 VPN，其余使用原有出口。';
  o = s.taboption('routes', form.DynamicList, 'routes', '指定网段');
  o.depends('routing_mode', 'rules'); o.retain = true;
  o.placeholder = '10.20.0.0/16';
  o.description = 'IPv4 CIDR 网段，可与三类域名规则同时使用。直连网段通过原有接口访问。';
  o.validate = function(section, value) {
   if (!value) return true;
   var parts = value.split('/');
   return parts.length === 2 && ipv4(parts[0]) && /^\d{1,2}$/.test(parts[1]) &&
    Number(parts[1]) >= 1 && Number(parts[1]) <= 32
     ? true : '请填写 IPv4 CIDR 网段，例如 10.20.0.0/16；全流量请切换模式。';
  };
  [
   ['domains', '完整域名', 'api.example.com', '只匹配完整域名，例如 api.example.com，不包括它的子域。'],
   ['domain_prefixes', '域名前缀', 'api.', '匹配域名开头，例如 api. 匹配 api.example.com；internal- 匹配 internal-app.example.com。'],
   ['domain_suffixes', '域名后缀', 'example.com', '匹配该域名及其全部子域，例如 example.com 和 api.example.com；不匹配 badexample.com。']
  ].forEach(function(item) {
   o = s.taboption('routes', form.DynamicList, item[0], item[1]);
   o.depends('routing_mode', 'rules'); o.retain = true; o.placeholder = item[2];
   o.description = item[3] + ' 不区分大小写。';
   o.validate = function(section, value) { return domain(value, item[0] === 'domain_prefixes'); };
  });
  o = s.taboption('routes', form.Value, 'vpn_dns', 'VPN DNS（可选）');
  o.placeholder = '自动使用 VPN 下发的 DNS'; o.datatype = 'ip4addr';
  o.description = '全流量或使用域名规则时需要可用的 VPN DNS。留空则使用 PPP 下发的地址；未下发时请填写。域名规则要求设备使用路由器 DNS，DoH/DoT 和已有缓存不会触发匹配；共享 IP 的其他域名也可能走 VPN。';
  o = s.taboption('routes', form.Value, 'probe_ip', '内网探测地址（可选）');
  o.placeholder = '10.20.0.10'; o.datatype = 'ip4addr';
  o.description = '填写允许 Ping 的内网 IP，连接后检查其是否经 VPN 可达。规则分流时应包含在指定网段内。';

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
   ['lcp_failure', 'PPP 保活失败次数', '5', 'range(1,20)', '连续失败达到此次数时判定连接中断。'],
   ['retry_interval', '自动重连间隔（秒）', '30', 'range(10,300)', '']
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
    E('style', {}, '.lp-status{padding:18px 20px;border:1px solid #dbe2ea;border-radius:8px;background:#f8fafc;margin:0 0 22px;color:#263548}.lp-status-heading{display:flex;align-items:center;gap:10px;margin-bottom:8px}.lp-badge{font-weight:600;padding:3px 10px;border-radius:20px;background:#e5eaf0;color:#536273}.lp-badge[data-phase="connected"]{background:#dcfce7;color:#166534}.lp-badge[data-phase="error"],.lp-badge[data-phase="conflict"]{background:#fee2e2;color:#991b1b}.lp-steps{display:flex;gap:28px;margin-top:16px;flex-wrap:wrap}.lp-step{font-size:13px;color:#59687b}.lp-step[data-ok="true"]{color:#15803d}.lp-actions{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}.lp-log{white-space:pre-wrap;overflow-wrap:anywhere;background:#152132;color:#d7e3f0;padding:18px;border-radius:8px;min-height:100px;max-height:300px;overflow:auto;font-size:12px;line-height:1.7}.lp-details{color:#69798b;font-size:12px;margin-top:12px}.lp-note{font-size:13px;color:#66778a;margin-top:16px}.lp-page details>summary{cursor:pointer;margin:18px 0 10px;font-weight:600}'),
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
  var reach = { yes: '可达', no: '未响应', no_route: '缺少路由', unknown: '未检测' };
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
   E('div', { 'class': 'lp-details' }, state.address ? 'VPN 地址：' + state.address + ' · 模式：' + (state.routing_mode === 'full' ? '全流量' : '规则分流') + ' · 接口：l2tp-vpn' : '接口：l2tp-vpn')
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

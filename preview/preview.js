'use strict';

// 预览仅模拟 LuCI 宿主，字段、校验与状态渲染来自实际插件页面。
function E(tag, attrs, children) {
 const node = document.createElement(tag);
 Object.entries(attrs || {}).forEach(([key, value]) => {
  if (typeof value === 'function') node.addEventListener(key, value);
  else if (value != null) node.setAttribute(key, value);
 });
 const add = child => {
  if (Array.isArray(child)) child.forEach(add);
  else if (child != null) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
 };
 add(children);
 return node;
}

const config = {
 server: '', username: '', password: '', psk: '', enabled: '0', reconnect: '1',
 routes: [], probe_ip: '', ike: 'aes256-sha256-modp2048', esp: 'aes256-sha1',
 local_id: '', remote_id: '', mtu: '1400', lcp_interval: '30', lcp_failure: '5', retry_interval: '30'
};
let scenario = 'disconnected';
let sequence = 0;
let state = { phase: 'disconnected', message: '尚未连接。', running: false, ipsec: false, ppp: false };
let log = '暂无连接日志。';
let currentView;
const uci = { load: async () => config, apply: async () => 0 };
const view = { extend: definition => definition };
const poll = { add: callback => setInterval(callback, 1000) };
const ui = {
 createHandlerFn: (self, fn) => async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try { await fn.call(self); }
  catch (error) { ui.addNotification(null, E('p', {}, error.message || String(error)), 'error'); }
  finally { button.disabled = false; await self.refresh(); }
 },
 addNotification: (title, node, type) => {
  const item = E('div', { class: 'notification ' + (type || ''), role: 'status' }, node);
  document.querySelector('#notifications').replaceChildren(item);
 }
};

function eventLog(message) {
 log = (log === '暂无连接日志。' ? '' : log + '\n') + new Date().toLocaleTimeString('zh-CN', {hour12:false}) + ' ' + message;
}
function setScenario(value) {
 sequence++;
 scenario = value;
 const connected = ['connected', 'probe_error'].includes(value);
 state = {
  phase: connected ? 'connected' : value === 'disconnected' ? 'disconnected' : 'error',
  message: connected ? 'VPN 已连接，指定内网路由已生效。' : value === 'psk_error' ? 'IPsec 协商失败，请检查 PSK、身份标识和加密算法。' : value === 'ppp_error' ? 'PPP 连接失败，请检查账号密码、PAP 设置和 UDP 1701 连通性。' : '尚未连接。',
  running: connected, ipsec: connected || value === 'ppp_error', ppp: connected,
  address: connected ? '10.20.1.25/32' : '', probe_ip: value === 'probe_error' ? '10.20.0.10' : config.probe_ip,
  reachable: value === 'probe_error' ? 'no' : connected && config.probe_ip ? 'yes' : 'unknown'
 };
 log = ''; eventLog(state.message);
 if (currentView) currentView.refresh();
}
const rpc = {
 declare: ({method}) => async () => {
  if (method === 'status') return {...state};
  if (method === 'logs') return {log};
  if (method === 'validate') return {ok:true, message:'配置检查通过。'};
  if (method === 'stop') {
   setScenario('disconnected');
   return {ok:true, message:'连接已停止。'};
  }
  if (method === 'start') {
   const token = ++sequence;
   state = {phase:'resolving', message:'正在解析服务器地址。', running:true, ipsec:false, ppp:false};
   log = ''; eventLog(state.message);
   const move = (delay, update) => setTimeout(() => {
    if (token !== sequence) return;
    Object.assign(state, update); eventLog(state.message); currentView.refresh();
   }, delay);
   move(700, {phase:'ipsec', message:'正在建立 IPsec 加密连接。'});
   if (scenario === 'psk_error') move(1800, {phase:'error', running:false, message:'IPsec 协商失败，请检查 PSK、身份标识和加密算法。'});
   else {
    move(1800, {phase:'ppp', ipsec:true, message:'IPsec 已建立，正在验证账号并连接 PPP。'});
    if (scenario === 'ppp_error') move(3200, {phase:'error', running:false, message:'PPP 连接失败，请检查账号密码和 PAP 设置。'});
    else move(3200, {phase:'connected', ipsec:true, ppp:true, address:'10.20.1.25/32', probe_ip:config.probe_ip,
     reachable:config.probe_ip ? scenario === 'probe_error' ? 'no' : 'yes' : 'unknown', message:'VPN 已连接，指定内网路由已生效。'});
   }
   return {ok:true, message:'已开始连接，请查看连接状态。'};
  }
 }
};

class Option {
 constructor(tab, type, key, title) { Object.assign(this, {tab,type,key,title,choices:[]}); }
 value(value, title) { this.choices.push([value,title]); }
 render() {
  this.field = E('div', {class:'cbi-value-field'});
  const value = config[this.key] ?? this.default ?? '';
  if (this.type === 'DummyValue') this.field.append(E('div', {class:'cbi-dummy'}, this.cfgvalue()));
  else if (this.type === 'DynamicList') {
   this.rows = E('div');
   const add = text => {
    const input = E('input', {type:'text', placeholder:this.placeholder || '', 'aria-label':this.title});
    input.value = text || '';
    const row = E('div', {class:'dynamic-row'}, [input, E('button', {type:'button', 'aria-label':'删除网段', click:()=>row.remove()}, '−')]);
    this.rows.append(row);
   };
   (Array.isArray(value) ? value : []).forEach(add);
   if (!this.rows.children.length) add('');
   this.field.append(this.rows, E('button', {type:'button', class:'add-row',click:()=>add('')}, '+ 添加网段'));
  } else {
   this.input = this.type === 'ListValue' ? E('select') : E('input', {type:this.type === 'Flag' ? 'checkbox' : this.password ? 'password' : 'text'});
   this.input.id = 'field-' + this.key;
   this.input.setAttribute('aria-label',this.title);
   if (this.type === 'ListValue') this.choices.forEach(([v,t])=>this.input.append(E('option',{value:v},t)));
   if (this.type === 'Flag') this.input.checked = value === '1'; else this.input.value = value;
   if (this.placeholder) this.input.placeholder = this.placeholder;
   if (this.password) this.field.append(E('div', {class:'secret-wrap'}, [this.input, E('button',{type:'button', 'aria-label':'显示'+this.title, click:event=>{
    this.input.type = this.input.type === 'password' ? 'text' : 'password';
    event.currentTarget.textContent = this.input.type === 'password' ? '显示' : '隐藏';
   }},'显示')]));
   else this.field.append(this.input);
  }
  if (this.description) this.field.append(E('div',{class:'cbi-value-description'},this.description));
  return E('div',{class:'cbi-value'},[E('label',{class:'cbi-value-title',for:'field-'+this.key},this.title),this.field]);
 }
 read() {
  if (this.type === 'DummyValue') return undefined;
  if (this.type === 'DynamicList') return [...this.rows.querySelectorAll('input')].map(i=>i.value.trim()).filter(Boolean);
  return this.type === 'Flag' ? this.input.checked ? '1' : '0' : this.input.value;
 }
 check(value) {
  let result = true;
  if (this.validate) {
   for (const v of Array.isArray(value) ? value : [value]) {
    result = this.validate('main',v); if (result !== true) break;
   }
  }
  if (result === true && this.datatype && value) {
   const range = this.datatype.match(/^range\((\d+),(\d+)\)$/);
   const max = this.datatype.match(/^maxlength\((\d+)\)$/);
   if (range && (!/^\d+$/.test(value) || +value < +range[1] || +value > +range[2])) result = '数值超出允许范围。';
   if (max && value.length > +max[1]) result = '输入内容过长。';
   if (this.datatype === 'ip4addr' && !ipv4Preview(value)) result = '请填写有效的 IPv4 地址。';
  }
  this.field.querySelectorAll('.validation-message').forEach(i=>i.remove());
  if (result !== true) this.field.append(E('div',{class:'validation-message'},result));
  return result;
 }
}
function ipv4Preview(value) { const p=value.split('.'); return p.length===4&&p.every(v=>/^\d{1,3}$/.test(v)&&+v<=255); }
class Section {
 constructor() { this.tabs=[];this.options=[]; }
 tab(key,title) { this.tabs.push([key,title]); }
 taboption(tab,type,key,title) { const option=new Option(tab,type,key,title);this.options.push(option);return option; }
}
class FormMap {
 constructor(config,title,description) { Object.assign(this,{title,description}); }
 section() { this.sectionObj = new Section();return this.sectionObj; }
 async render() {
  const s=this.sectionObj;
  const tabs=E('div',{class:'cbi-tabmenu',role:'tablist'});
  const panels=E('div');
  const show=key=>{
   tabs.querySelectorAll('button').forEach(b=>{b.classList.toggle('active',b.dataset.tab===key);b.setAttribute('aria-selected',String(b.dataset.tab===key));});
   panels.querySelectorAll('[data-panel]').forEach(p=>p.hidden=p.dataset.panel!==key);
  };
  for(const [key,title] of s.tabs){
   tabs.append(E('button',{type:'button','data-tab':key,role:'tab',click:()=>show(key)},title));
   panels.append(E('div',{'data-panel':key,role:'tabpanel'},s.options.filter(o=>o.tab===key).map(o=>o.render())));
  }
  show(s.tabs[0][0]);
  return E('div',{class:'cbi-map'},[tabs,panels]);
 }
 async save() {
  const updated={};let firstError;
  for(const option of this.sectionObj.options){
   const value=option.read();if(value===undefined)continue;
   const result=option.check(value);
   if(result!==true)firstError=firstError||result;
   updated[option.key]=value;
  }
  if(firstError)throw new Error(firstError);
  Object.assign(config,updated);
 }
}
const form={Map:FormMap,NamedSection:Section,Value:'Value',Flag:'Flag',ListValue:'ListValue',DynamicList:'DynamicList',DummyValue:'DummyValue'};
document.querySelector('#scenario').addEventListener('change',e=>setScenario(e.target.value));

async function boot() {
 const source=await fetch('l2tp-ipsec-client.js').then(r=>{if(!r.ok)throw new Error('无法加载实际页面代码');return r.text();});
 currentView=new Function('view','form','rpc','poll','ui','uci','E',source)(view,form,rpc,poll,ui,uci,E);
 document.querySelector('#app').append(await currentView.render(await currentView.load()));
}
boot().catch(error=>ui.addNotification(null,E('p',{},error.message),'error'));

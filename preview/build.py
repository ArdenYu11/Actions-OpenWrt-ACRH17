#!/usr/bin/env python3
"""从实际 LuCI 页面生成可双击打开的单文件预览。"""
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREVIEW = ROOT / 'preview'
SOURCE = ROOT / 'packages/luci-app-l2tp-ipsec-client/htdocs/luci-static/resources/view/l2tp-ipsec-client.js'
shutil.copy2(SOURCE, PREVIEW / 'l2tp-ipsec-client.js')
source = SOURCE.read_text()
script = (PREVIEW / 'preview.js').read_text()
loader = "const source=await fetch('l2tp-ipsec-client.js').then(r=>{if(!r.ok)throw new Error('无法加载实际页面代码');return r.text();});"
import json
script = script.replace(loader, 'const source=' + json.dumps(source, ensure_ascii=False) + ';')
document = (PREVIEW / 'index.html').read_text()
document = document.replace('<link rel="stylesheet" href="preview.css">', '<style>' + (PREVIEW / 'preview.css').read_text() + '</style>')
document = document.replace('<script src="preview.js"></script>', '<script>' + script.replace('</script', '<\\/script') + '</script>')
destination = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else PREVIEW / 'standalone.html'
destination.write_text(document)
print(destination)

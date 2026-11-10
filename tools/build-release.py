#!/usr/bin/env python3
"""Validate version consistency and produce an installation ZIP, without secrets."""
import re,zipfile,json,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1];plugin=root/'lnkta-security-guard';dist=root/'dist';dist.mkdir(exist_ok=True)
source=(plugin/'lnkta-security-guard.php').read_text()
m=re.search(r'^ \* Version: (\d+\.\d+\.\d+)\s*$',source,re.M)
if not m:raise SystemExit('Missing standard plugin version')
version=m[1]
for path in [plugin/'updater.php',plugin/'hardening.php']:
 if not re.search(r"const VERSION\s*=\s*'"+re.escape(version)+r"'",path.read_text()):raise SystemExit(f'Version mismatch: {path.name}')
archive=dist/f'lnkta-security-guard-v{version}.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(plugin.rglob('*')):
  if p.is_file() and '__pycache__' not in p.parts and p.suffix in ['.php','.md','.py']:
   z.write(p,p.relative_to(root).as_posix())
(dist/'version.txt').write_text(version+'\n')
print(json.dumps({'version':version,'zip':str(archive)}))

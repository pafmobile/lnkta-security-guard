#!/usr/bin/env python3
"""Run only on a trusted release computer; requires Python cryptography.
Generate once: sign-release.py keygen /secure/outside-repo/guard-release.key
Sign a ZIP: sign-release.py sign --key /secure/outside-repo/guard-release.key --repository OWNER/REPO --version 1.5.0 --zip /path/lnkta-security-guard-v1.5.0.zip --output /path/manifest.json
Never upload the private key to WordPress, GitHub source or release assets.
"""
import argparse, base64, hashlib, json, os, re
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
k=sub.add_parser('keygen');k.add_argument('keyfile',type=Path)
s=sub.add_parser('sign');s.add_argument('--key',type=Path,required=True);s.add_argument('--repository',required=True);s.add_argument('--version',required=True);s.add_argument('--zip',type=Path,required=True);s.add_argument('--output',type=Path,required=True)
a=p.parse_args()
if a.action=='keygen':
    key=Ed25519PrivateKey.generate()
    fd=os.open(a.keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
    print('Public key for wp-config.php:',key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex())
else:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+',a.repository):p.error('Invalid owner/repository')
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?',a.version):p.error('Invalid version')
    if a.zip.name!=f'lnkta-security-guard-v{a.version}.zip':p.error('ZIP filename must match the version')
    key=Ed25519PrivateKey.from_private_bytes(a.key.read_bytes())
    m={'repository':a.repository,'slug':'lnkta-security-guard','version':a.version,'requires_php':'7.4','requires_wp':'6.0','sha256':hashlib.sha256(a.zip.read_bytes()).hexdigest(),'package_url':f'https://github.com/{a.repository}/releases/download/v{a.version}/lnkta-security-guard-v{a.version}.zip'}
    payload=json.dumps(m,separators=(',',':'),sort_keys=True).encode()
    envelope={'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(key.sign(payload)).decode()}
    a.output.write_text(json.dumps(envelope,indent=2)+'\n')
    print('Created signed manifest:',a.output)

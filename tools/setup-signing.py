#!/usr/bin/env python3
"""Run ONCE on your own trusted computer, never on WordPress or a public runner.
Requires: python -m pip install cryptography
Optional GitHub setup: python tools/setup-signing.py --github
Requires gh CLI already authenticated with permission to set repository secrets.
"""
import argparse,base64,os,shutil,subprocess
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--github',action='store_true');a=p.parse_args()
repo='pafmobile/lnkta-security-guard';directory=Path.home()/'.lnkta-release-signing';directory.mkdir(mode=0o700,exist_ok=True)
path=directory/'security-guard-ed25519.key'
if path.exists():key=Ed25519PrivateKey.from_private_bytes(path.read_bytes())
else:
 key=Ed25519PrivateKey.generate();fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'wb') as f:f.write(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption());public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
secret_path=directory/'github-secret.txt';fd=os.open(secret_path,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
with os.fdopen(fd,'w') as f:f.write(base64.b64encode(raw).decode())
(directory/'public-key.txt').write_text(public+'\n')
print('Public key (safe to share):',public)
print('Private signing files saved locally outside the repository:',directory)
print('Keep these files private and keep an encrypted offline backup. Never upload them as repository files.')
if a.github:
 if not shutil.which('gh'):raise SystemExit('GitHub CLI not found. Add the secret/variable manually following README.md.')
 subprocess.run(['gh','secret','set','LNKTA_RELEASE_SIGNING_KEY','--repo',repo],input=base64.b64encode(raw),check=True)
 subprocess.run(['gh','variable','set','LNKTA_RELEASE_PUBLIC_KEY','--repo',repo,'--body',public],check=True)
 print('GitHub Actions signing secret and public-key variable configured.')
else:print('In GitHub Settings > Secrets and variables > Actions, add LNKTA_RELEASE_SIGNING_KEY from github-secret.txt; add variable LNKTA_RELEASE_PUBLIC_KEY from public-key.txt.')

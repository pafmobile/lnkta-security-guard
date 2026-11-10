#!/usr/bin/env python3
"""Read signing secret from CI environment; publish only manifest and public key."""
import os,base64,json,hashlib,re
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=Path(__file__).resolve().parents[1];dist=root/'dist';version=(dist/'version.txt').read_text().strip()
repo=os.environ['GITHUB_REPOSITORY']
if repo!='pafmobile/lnkta-security-guard':raise SystemExit('Unexpected release repository')
encoded=os.environ.get('LNKTA_RELEASE_SIGNING_KEY','')
if not encoded:raise SystemExit('Signing key missing. Run the one-time setup in README.md; no release was published.')
try:key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(encoded,validate=True))
except Exception:raise SystemExit('Signing key has invalid format; no release was published.')
public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
if public!=os.environ.get('LNKTA_RELEASE_PUBLIC_KEY','').strip():raise SystemExit('Public-key variable does not match signing key; no release was published.')
archive=dist/f'lnkta-security-guard-v{version}.zip'
m={'repository':repo,'slug':'lnkta-security-guard','version':version,'requires_php':'7.4','requires_wp':'6.0','sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'package_url':f'https://github.com/{repo}/releases/download/v{version}/{archive.name}'}
payload=json.dumps(m,separators=(',',':'),sort_keys=True).encode();sig=key.sign(payload);key.public_key().verify(sig,payload)
(dist/'manifest.json').write_text(json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(sig).decode()},indent=2)+'\n')
(dist/'release-public-key.txt').write_text(public+'\n')
print('Manifest signed and verified. No private key files were written by this CI step.')

"""Evidence Package v1 primitives. Canonicalization is local v1, not RFC 8785."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

VERSION = '0.1.0'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024

class Refusal(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def decode(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj: raise Refusal('duplicate_json_key')
            obj[key] = value
        return obj
    def reject(value): raise Refusal('nonfinite_json')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value):
        raise Refusal('invalid_identifier')
    return value

def read_file(path, maximum=MAX_FILE, private=False):
    path = Path(path)
    # O_NOFOLLOW rejects the final link; directory components must be checked by callers.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode): raise Refusal('regular_file_required')
        if private and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
            raise Refusal('private_key_permissions')
        raw = stream.read(maximum + 1)
    if len(raw) > maximum: raise Refusal('file_size_limit')
    return raw

def checked_dir(path):
    path = Path(path).absolute()
    if '..' in path.parts: raise Refusal('parent_path_not_allowed')
    for part in [*reversed(path.parents), path]:
        if part.is_symlink(): raise Refusal('symlink_directory')
    if not path.is_dir(): raise Refusal('directory_required')
    return path

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def public_key(path):
    raw = read_file(path, 32)
    return Ed25519PublicKey.from_public_bytes(raw), digest(raw)

def seal(value, private_path, trusted_path):
    key = Ed25519PrivateKey.from_private_bytes(read_file(private_path, 32, private=True))
    raw = key.public_key().public_bytes_raw()
    if raw != read_file(trusted_path, 32): raise Refusal('signer_not_trusted')
    return dict(payload=value, algorithm='Ed25519', keyId=digest(raw),
                signature=base64.b64encode(key.sign(canonical(value))).decode())

def unseal(envelope, trusted_path):
    if not isinstance(envelope, dict) or set(envelope) != {'payload','algorithm','keyId','signature'}:
        raise Refusal('invalid_signature_envelope')
    key, key_id = public_key(trusted_path)
    if envelope['algorithm'] != 'Ed25519' or envelope['keyId'] != key_id:
        raise Refusal('untrusted_signer')
    key.verify(base64.b64decode(envelope['signature'], validate=True), canonical(envelope['payload']))
    return envelope['payload']

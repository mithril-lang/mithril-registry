"""Private bounded directory-listing cache; every child still gets fresh lstat."""
import json
import os
import stat
import uuid
from types import SimpleNamespace


class ListingIndex:
    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
        self.records = {}
        self.reused = self.enumerated = 0
        try:
            info = os.lstat(self.filename)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
                return
            with open(self.filename, encoding="utf-8") as handle:
                data = json.load(handle)
            if data.get("version") != 1:
                return
            count = 0
            for record in data.get("directories", [])[:2000]:
                names = record.get("names")
                if not isinstance(record.get("path"), str) or not os.path.isabs(record["path"]) or not isinstance(record.get("signature"), list) or not isinstance(names, list):
                    continue
                if not all(isinstance(n, str) and n not in ("", ".", "..") and not any(c in n for c in ("/", "\\", "\x00")) for n in names):
                    continue
                count += len(names) + 1
                if count > 20000:
                    break
                self.records[record["path"]] = record
        except (OSError, ValueError, TypeError, AttributeError):
            self.records = {}

    def open(self, directory, info):
        signature = [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]
        record = self.records.get(directory)
        if record and record["signature"] == signature:
            self.reused += 1
            return CachedCursor(iter(SimpleNamespace(path=os.path.join(directory, n)) for n in record["names"]))
        self.enumerated += 1
        self.records.pop(directory, None)
        return RecordingCursor(os.scandir(directory), lambda names: self.records.update({directory: dict(path=directory, signature=signature, names=names)}))

    def save(self):
        records, count = [], 0
        for record in reversed(list(self.records.values())):
            count += len(record["names"]) + 1
            if count > 20000 or len(records) >= 2000:
                break
            records.append(record)
        body = json.dumps(dict(version=1, directories=records), ensure_ascii=False).encode("utf-8")
        if len(body) > 4 * 1024 * 1024:
            return
        temporary = self.filename + "." + uuid.uuid4().hex + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.filename), mode=0o700, exist_ok=True)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
            os.replace(temporary, self.filename)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass


class CachedCursor:
    def __init__(self, iterator):
        self.iterator = iterator

    def __next__(self):
        return next(self.iterator)

    def close(self):
        pass


class RecordingCursor(CachedCursor):
    def __init__(self, iterator, commit):
        super().__init__(iterator)
        self.names, self.commit, self.complete = [], commit, False

    def __next__(self):
        try:
            item = super().__next__()
            self.names.append(item.name)
            return item
        except StopIteration:
            self.complete = True
            raise

    def close(self):
        self.iterator.close()
        if self.complete:
            self.commit(self.names)

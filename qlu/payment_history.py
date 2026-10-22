"""Durable, per-wallet private-network payment intent and confirmation journal.

Public payment metadata and an optional signed outbox are stored, never spending keys.
The signed bytes remain private to the local journal. The caller MUST wait for
``before_broadcast`` to return successfully before submitting a transaction.
An interrupted ``preparing`` operation is therefore provably not submitted by
this protocol; a ``pending`` operation can never be cleared based on absence.
Received payments are independently verified observations, never authorizations
to broadcast. Their pending status does not block unrelated outgoing payments.
This POSIX store does not claim protection against a malicious process running
as the same user or against rollback of the entire application data directory.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

try:
    from . import payment_conflicts, payment_resume, protocol
except ImportError:
    import payment_conflicts
    import payment_resume
    import protocol

MAX_RECORDS = 10_000
MAX_BYTES = 16 * 1024 * 1024
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
OPERATION = re.compile(r"[0-9a-f]{32}\Z")
AMOUNT = re.compile(r"(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?\Z")
REASONS = {"not_found", "mempool", "network_unavailable", "scan_limit"}
RECEIVE_DOMAIN = b"QLU payment history v2 / received transaction\0"
MESSAGES = {
    "history_unavailable": "Payment history is unavailable. Do not repeat a payment until its history is checked.",
    "payment_pending": "A payment is still unresolved. Check its confirmation before sending again.",
    "history_full": "Payment history is full. New payments are disabled until the history is maintained.",
}


class HistoryError(RuntimeError):
    def __init__(self, code="history_unavailable"):
        self.code = code if code in MESSAGES else "history_unavailable"
        self.message = MESSAGES[self.code]
        super().__init__(self.message)


def _valid(condition):
    if not condition:
        raise HistoryError()


def _hex(value, pattern=HEX256):
    _valid(type(value) is str and pattern.fullmatch(value) is not None)
    return value


def _amount(value, *, zero=False):
    _valid(type(value) is str and len(value) <= 17 and AMOUNT.fullmatch(value) is not None)
    whole, _, fraction = value.partition(".")
    units = int(whole) * 100_000_000 + int(fraction.ljust(8, "0") or "0")
    _valid((0 if zero else 1) <= units <= 21_000_000 * 100_000_000)
    return f"{units // 100_000_000}.{units % 100_000_000:08d}"


def _recipient(value):
    # Address validity belongs to the network adapter; this bound prevents
    # arbitrary blobs or control characters being persisted as public metadata.
    _valid(type(value) is str and 1 <= len(value) <= 128 and value.isascii()
           and all(32 <= ord(character) <= 126 for character in value))
    return value


def _integer(value, maximum=2**53 - 1):
    _valid(type(value) is int and 0 <= value <= maximum)
    return value


def _details(value):
    _valid(type(value) is dict and set(value) <= {"recipient", "amount", "fee"})
    result = {}
    for key, item in value.items():
        result[key] = _recipient(item) if key == "recipient" else _amount(item, zero=key == "fee")
    return result


def _receive_operation(txid):
    return hashlib.sha256(RECEIVE_DOMAIN + bytes.fromhex(_hex(txid))).hexdigest()[:32]


def _transaction(value, txid):
    try:
        payment_conflicts.validate_transaction(value, txid)
    except (ValueError, TypeError):
        raise HistoryError() from None
    return value


def _conflict(value, transaction, txid):
    try:
        payment_conflicts.validate_conflict(value, transaction, txid)
    except (ValueError, TypeError):
        raise HistoryError() from None
    return value


def _record(value, *, version=4):
    common = {"operation_id", "kind", "status", "created_at", "updated_at"}
    _valid(type(value) is dict and common <= set(value))
    _hex(value["operation_id"], OPERATION)
    kinds = ("send", "funding", "receive") if version >= 2 else ("send", "funding")
    _valid(type(value["kind"]) is str and value["kind"] in kinds)
    incoming = value["kind"] == "receive"
    intent = {"recipient", "amount"} if incoming else {"recipient", "amount", "fee"}
    broadcast = intent | {"txid", "start_height"}
    statuses = ("preparing", "not_sent", "pending", "confirmed", "conflicted") if version >= 3 else ("preparing", "not_sent", "pending", "confirmed")
    _valid(value["status"] in statuses
           and type(value["status"]) is str)
    if incoming:
        _valid(value["status"] in ("pending", "confirmed") and "txid" in value)
        _valid(value["operation_id"] == _receive_operation(value["txid"]))
    _integer(value["created_at"])
    _integer(value["updated_at"])
    _valid(value["updated_at"] >= value["created_at"])
    for key in intent & set(value):
        normalized = _details({key: value[key]})[key]
        _valid(normalized == value[key])
    if value["status"] in ("preparing", "not_sent"):
        _valid(set(value) <= common | intent)
    else:
        _valid(broadcast <= set(value))
        _hex(value["txid"])
        _integer(value["start_height"], 2**31 - 1)
        metadata = set()
        if "transaction" in value:
            _valid(version >= 3 and not incoming)
            _transaction(value["transaction"], value["txid"])
            metadata.add("transaction")
        if "signed_transaction" in value or "spent_outputs" in value:
            _valid(version >= 4 and not incoming and "transaction" in value
                   and {"signed_transaction", "spent_outputs"} <= set(value))
            try:
                payment_resume.validate_resume_record(value)
            except (ValueError, TypeError):
                raise HistoryError() from None
            metadata |= {"signed_transaction", "spent_outputs"}
        if "conflict" in value:
            _valid(version >= 3 and not incoming and "transaction" in value)
            _conflict(value["conflict"], value["transaction"], value["txid"])
            metadata.add("conflict")
        if value["status"] == "confirmed":
            _valid(set(value) == common | broadcast | metadata | {"block", "confirmed_nodes"})
            _hex(value["block"])
            _valid(type(value["confirmed_nodes"]) is int and value["confirmed_nodes"] == 4)
        elif value["status"] == "conflicted":
            _valid(not incoming and "transaction" in value
                   and common | broadcast | {"transaction", "conflict", "confirmed_nodes"} <= set(value)
                   and set(value) <= common | broadcast | metadata | {"transaction", "conflict", "confirmed_nodes", "block"})
            _conflict(value["conflict"], value["transaction"], value["txid"])
            _valid(type(value["confirmed_nodes"]) is int and value["confirmed_nodes"] == 4)
            if "block" in value: _hex(value["block"])
        else:
            _valid(set(value) <= common | broadcast | metadata | {"status_reason", "confirmed_nodes", "block"})
            if "block" in value:
                _hex(value["block"])
            if "status_reason" in value:
                _valid(type(value["status_reason"]) is str and value["status_reason"] in REASONS)
            if "confirmed_nodes" in value:
                _integer(value["confirmed_nodes"], 4)
    return value


def _pairs(items):
    result = {}
    for name, value in items:
        _valid(name not in result)
        result[name] = value
    return result


def _parent(path):
    _valid(path.is_absolute() and ".." not in path.parts and path.name not in ("", ".", ".."))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        _valid(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _identity(info):
    return info.st_dev, info.st_ino


def _private(info, *, directory=False):
    _valid(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    _valid(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


class PaymentHistory:
    def __init__(self, directory: Path, wallet_id: str):
        self.wallet_id = wallet_id
        self._directory_fd = self._lock_fd = None
        self._directory_identity = self._lock_identity = self._journal_identity = None
        self._digest = None
        self._poisoned = False
        self._closed = False
        self._document = None
        try:
            self.directory = Path(directory)
            _hex(wallet_id)
            self._receive_recipient = protocol.address_for({"key_commitment": wallet_id})
            self._name = wallet_id + ".json"
            self._lock_name = wallet_id + ".lock"
            parent, name = _parent(self.directory)
            try:
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
                self._directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                             dir_fd=parent)
                info = os.fstat(self._directory_fd)
                _private(info, directory=True)
                self._directory_identity = _identity(info)
            finally:
                os.close(parent)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            try:
                self._lock_fd = os.open(self._lock_name, flags | os.O_CREAT | os.O_EXCL,
                                        0o600, dir_fd=self._directory_fd)
                fresh = True
            except FileExistsError:
                self._lock_fd = os.open(self._lock_name, flags, dir_fd=self._directory_fd)
                fresh = False
            info = os.fstat(self._lock_fd)
            _private(info)
            _valid(info.st_size == 0)
            self._lock_identity = _identity(info)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check_location()
            if fresh:
                os.fsync(self._lock_fd)
                os.fsync(self._directory_fd)
                self._write(self._empty(), initial=True)
            else:
                data, identity = self._read()
                document = self._parse(data, allow_legacy=True)
                self._document = document
                self._journal_identity = identity
                self._digest = hashlib.sha256(data).digest()
            recovered = copy.deepcopy(self._document)
            changed = recovered["version"] < 4
            recovered["version"] = 4
            for entry in recovered["records"]:
                if entry["kind"] in ("send", "funding") and entry["status"] == "preparing":
                    entry["status"] = "not_sent"
                    entry["updated_at"] = max(entry["updated_at"], int(time.time()))
                    changed = True
            if changed:
                self._write(recovered)
        except Exception:
            self._poisoned = True
            self.close()
            raise HistoryError() from None

    def _empty(self):
        return {"format": "qlu-payment-history", "version": 4, "network_id": protocol.NETWORK,
                "genesis_hash": protocol.GENESIS, "wallet_id": self.wallet_id, "records": []}

    def _parse(self, data, *, allow_legacy=False):
        _valid(1 <= len(data) <= MAX_BYTES)
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(HistoryError()))
        _valid(type(value) is dict and set(value) == set(self._empty()))
        _valid(type(value["version"]) is int and value["version"] in ((1, 2, 3, 4) if allow_legacy else (4,)))
        for key, expected in self._empty().items():
            if key not in ("records", "version"):
                _valid(type(value[key]) is type(expected) and value[key] == expected)
        _valid(type(value["records"]) is list and len(value["records"]) <= MAX_RECORDS)
        identities = set()
        transactions, received_transactions = set(), set()
        for entry in value["records"]:
            # Legacy data must satisfy its original schema before conversion.
            # In particular, a v1 receive entry is never accepted as migration.
            _record(entry, version=value["version"])
            _valid(entry["operation_id"] not in identities)
            identities.add(entry["operation_id"])
            if "txid" in entry:
                txid = entry["txid"]
                _valid(txid not in received_transactions)
                if entry["kind"] == "receive":
                    _valid(entry["recipient"] == self._receive_recipient)
                    _valid(txid not in transactions)
                    received_transactions.add(txid)
                transactions.add(txid)
        return value

    def _check_location(self):
        _valid(not self._closed and not self._poisoned)
        info = os.fstat(self._directory_fd)
        _private(info, directory=True)
        _valid(_identity(info) == self._directory_identity)
        parent, name = _parent(self.directory)
        try:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _private(named, directory=True)
            _valid(_identity(named) == self._directory_identity)
        finally:
            os.close(parent)
        info = os.fstat(self._lock_fd)
        _private(info)
        named = os.stat(self._lock_name, dir_fd=self._directory_fd, follow_symlinks=False)
        _private(named)
        _valid(_identity(info) == self._lock_identity == _identity(named) and info.st_size == 0)

    def _read(self):
        fd = os.open(self._name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=self._directory_fd)
        try:
            before = os.fstat(fd)
            _private(before)
            _valid(1 <= before.st_size <= MAX_BYTES)
            chunks, remaining = [], MAX_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            named = os.stat(self._name, dir_fd=self._directory_fd, follow_symlinks=False)
            _private(after)
            _private(named)
            _valid(_identity(before) == _identity(after) == _identity(named)
                   and before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns)
            data = b"".join(chunks)
            _valid(len(data) == before.st_size and len(data) <= MAX_BYTES)
            return data, _identity(after)
        finally:
            os.close(fd)

    def _ensure(self):
        try:
            self._check_location()
            data, identity = self._read()
            _valid(identity == self._journal_identity and hashlib.sha256(data).digest() == self._digest)
        except Exception:
            self._poisoned = True
            raise HistoryError() from None

    def _write(self, document, *, initial=False):
        temporary = "." + self.wallet_id + "." + uuid.uuid4().hex + ".tmp"
        temporary_identity = None
        fd = None
        try:
            data = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
            self._parse(data)
            self._check_location() if initial else self._ensure()
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self._directory_fd)
            info = os.fstat(fd)
            _private(info)
            temporary_identity = _identity(info)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                _valid(written > 0)
                view = view[written:]
            os.fsync(fd)
            self._check_location() if initial else self._ensure()
            named = os.stat(temporary, dir_fd=self._directory_fd, follow_symlinks=False)
            _private(named)
            _valid(_identity(named) == temporary_identity)
            if initial:
                # link is exclusive: an existing or concurrently created journal
                # is never overwritten during first initialization.
                os.link(temporary, self._name, src_dir_fd=self._directory_fd,
                        dst_dir_fd=self._directory_fd, follow_symlinks=False)
                os.unlink(temporary, dir_fd=self._directory_fd)
            else:
                os.replace(temporary, self._name, src_dir_fd=self._directory_fd,
                           dst_dir_fd=self._directory_fd)
            os.fsync(self._directory_fd)
            published, identity = self._read()
            _valid(published == data and identity == temporary_identity)
            self._document = copy.deepcopy(document)
            self._journal_identity = identity
            self._digest = hashlib.sha256(data).digest()
        except Exception:
            self._poisoned = True
            raise HistoryError() from None
        finally:
            if fd is not None:
                os.close(fd)
            if temporary_identity is not None:
                try:
                    named = os.stat(temporary, dir_fd=self._directory_fd, follow_symlinks=False)
                    if _identity(named) == temporary_identity:
                        os.unlink(temporary, dir_fd=self._directory_fd)
                except OSError:
                    pass

    @property
    def blocked(self):
        if self._closed or self._poisoned:
            return True
        self._ensure()
        return any(entry["kind"] in ("send", "funding") and entry["status"] in ("preparing", "pending")
                   for entry in self._document["records"])

    def records(self):
        self._ensure()
        return copy.deepcopy(self._document["records"])

    @staticmethod
    def _resume_available(entry, entries):
        return payment_resume.locally_resumable(entry) and not any(
            other["operation_id"] != entry["operation_id"] and other["kind"] in ("send", "funding")
            and other["status"] in ("preparing", "pending") for other in entries)

    def public_records(self, limit=20):
        _valid(type(limit) is int and 1 <= limit <= 100)
        entries = self.records()
        return [{**{key: value for key, value in entry.items()
                     if key not in {"start_height", "transaction", "signed_transaction", "spent_outputs"}},
                 "resume_available": self._resume_available(entry, entries)}
                for entry in reversed(entries[-limit:])]

    def _change(self, operation_id):
        self._ensure()
        _hex(operation_id, OPERATION)
        document = copy.deepcopy(self._document)
        matches = [item for item in document["records"] if item["operation_id"] == operation_id]
        _valid(len(matches) == 1)
        entry = matches[0]
        return document, entry

    @staticmethod
    def _touch(entry):
        entry["updated_at"] = max(entry["updated_at"], int(time.time()))

    def begin(self, kind, *, operation_id=None, **details):
        self._ensure()
        _valid(type(kind) is str and kind in ("send", "funding"))
        details = _details(details)
        identifier = uuid.uuid4().hex if operation_id is None else _hex(operation_id, OPERATION)
        _valid(all(entry["operation_id"] != identifier for entry in self._document["records"]))
        if self.blocked:
            raise HistoryError("payment_pending")
        if len(self._document["records"]) >= MAX_RECORDS:
            raise HistoryError("history_full")
        now = int(time.time())
        entry = {"operation_id": identifier, "kind": kind, "status": "preparing",
                 "created_at": now, "updated_at": now, **details}
        document = copy.deepcopy(self._document)
        document["records"].append(entry)
        self._write(document)
        return identifier

    def before_broadcast(self, operation_id, data):
        document, entry = self._change(operation_id)
        required = {"txid", "recipient", "amount", "fee", "start_height"}
        _valid(entry["kind"] in ("send", "funding") and entry["status"] == "preparing" and type(data) is dict
               and required <= set(data) <= required | {"transaction", "signed_transaction", "spent_outputs"})
        normalized = _details({key: data[key] for key in ("recipient", "amount", "fee")})
        _hex(data["txid"])
        _integer(data["start_height"], 2**31 - 1)
        for key, value in normalized.items():
            _valid(key not in entry or entry[key] == value)
        entry.update(normalized, txid=data["txid"], start_height=data["start_height"], status="pending")
        if "transaction" in data:
            entry["transaction"] = _transaction(data["transaction"], data["txid"])
        if "signed_transaction" in data or "spent_outputs" in data:
            _valid({"transaction", "signed_transaction", "spent_outputs"} <= set(data))
            entry["signed_transaction"] = data["signed_transaction"]
            entry["spent_outputs"] = copy.deepcopy(data["spent_outputs"])
        _record(entry)
        self._touch(entry)
        self._write(document)

    def assert_resume(self, operation_id, signed_transaction):
        """Check the durable original outbox immediately before its rebroadcast.

        No new operation is created and no status is cleared. Re-reading through
        _change enforces current storage ownership and tamper checks as well.
        """
        document, entry = self._change(operation_id)
        _valid(self._resume_available(entry, document["records"])
               and type(signed_transaction) is str
               and signed_transaction == entry["signed_transaction"])
        try:
            payment_resume.validate_resume_record(entry)
        except (ValueError, TypeError):
            raise HistoryError() from None

    def finish(self, operation_id, receipt):
        _, entry = self._change(operation_id)
        _valid(entry["kind"] in ("send", "funding"))
        _valid(type(receipt) is dict and receipt.get("status", "confirmed") == "confirmed")
        self.update(operation_id, {**receipt, "status": "confirmed"})

    def fail_before_broadcast(self, operation_id):
        document, entry = self._change(operation_id)
        _valid(entry["kind"] in ("send", "funding"))
        if entry["status"] == "preparing":
            entry["status"] = "not_sent"
            self._touch(entry)
            self._write(document)

    def observe_received(self, receipt):
        """Store an incoming payment after the network verifies all four nodes.

        This method validates the adapter's public receipt, not the blockchain
        itself. The caller must obtain it from ``verify_received_payment``.
        Re-observation confirms an existing receive entry without duplicating
        it; a matching outgoing transaction retains its original identity.
        """
        self._ensure()
        fields = {"txid", "recipient", "amount", "start_height", "block", "confirmed_nodes"}
        _valid(type(receipt) is dict and set(receipt) in (fields, fields | {"status"})
               and receipt.get("status", "confirmed") == "confirmed")
        normalized = {**_details({key: receipt[key] for key in ("recipient", "amount")}),
                      "txid": _hex(receipt["txid"]), "block": _hex(receipt["block"]),
                      "start_height": _integer(receipt["start_height"], 2**31 - 1),
                      "confirmed_nodes": receipt["confirmed_nodes"]}
        _valid(type(normalized["confirmed_nodes"]) is int and normalized["confirmed_nodes"] == 4)
        _valid(normalized["recipient"] == self._receive_recipient)
        for entry in self._document["records"]:
            if entry.get("txid") == normalized["txid"]:
                if entry["kind"] == "receive":
                    # A fresh four-node proof may locate the same transaction
                    # at another height after a reorg. Retain its original
                    # lookup origin, just as reconciliation does.
                    self.update(entry["operation_id"], {**normalized, "status": "confirmed",
                                                        "start_height": entry["start_height"]})
                    return next(copy.deepcopy(item) for item in self._document["records"]
                                if item["operation_id"] == entry["operation_id"])
                return copy.deepcopy(entry)
        identifier = _receive_operation(normalized["txid"])
        _valid(all(entry["operation_id"] != identifier for entry in self._document["records"]))
        if len(self._document["records"]) >= MAX_RECORDS:
            raise HistoryError("history_full")
        now = int(time.time())
        entry = {"operation_id": identifier, "kind": "receive", "status": "confirmed",
                 "created_at": now, "updated_at": now, **normalized}
        _record(entry)
        document = copy.deepcopy(self._document)
        document["records"].append(entry)
        self._write(document)
        return copy.deepcopy(entry)

    def update(self, operation_id, status):
        document, entry = self._change(operation_id)
        previous = copy.deepcopy(entry)
        _valid(entry["status"] in ("pending", "confirmed", "conflicted") and type(status) is dict)
        _valid("status" in status and status["status"] in ("pending", "confirmed", "conflicted"))
        intent = {"txid", "recipient", "amount", "start_height"}
        if entry["kind"] != "receive":
            intent.add("fee")
        allowed = intent | {"status", "block", "confirmed_nodes", "status_reason"}
        if entry["kind"] != "receive":
            allowed |= {"transaction", "conflict", "signed_transaction", "spent_outputs"}
        _valid(set(status) <= allowed)
        if "transaction" in status:
            _valid("transaction" in entry and type(status["transaction"]) is str
                   and status["transaction"] == entry["transaction"])
        for field in ("signed_transaction", "spent_outputs"):
            if field in status:
                _valid(field in entry and type(status[field]) is type(entry[field])
                       and status[field] == entry[field])
        for key in intent:
            if key in status:
                value = _amount(status[key], zero=key == "fee") if key in ("amount", "fee") else status[key]
                _valid(type(value) is type(entry[key]) and value == entry[key])
        if status["status"] == "confirmed":
            _valid((intent - {"start_height"}) | {"status", "block", "confirmed_nodes"} <= set(status)
                   and "status_reason" not in status and "conflict" not in status)
            entry.update(status="confirmed", block=_hex(status["block"]), confirmed_nodes=status["confirmed_nodes"])
            entry.pop("status_reason", None)
        elif status["status"] == "conflicted":
            _valid(entry["kind"] != "receive" and "transaction" in entry
                   and (intent - {"start_height"}) | {"status", "conflict", "confirmed_nodes"} <= set(status)
                   and "status_reason" not in status)
            if "block" in status: _valid(status["block"] == entry.get("block"))
            entry.update(status="conflicted", confirmed_nodes=status["confirmed_nodes"],
                         conflict=copy.deepcopy(_conflict(status["conflict"], entry["transaction"], entry["txid"])))
            entry.pop("status_reason", None)
        else:
            _valid("conflict" not in status)
            if "block" in status:
                _valid(status["block"] == entry.get("block"))
            entry["status"] = "pending"
            # Retain the last-known block only as a lookup hint. The network
            # must recheck active-chain membership before confirming again.
            # Losing this hint on a transient failure can strand old payments
            # outside the bounded historical scan window indefinitely.
            entry.pop("confirmed_nodes", None)
            # Preserve any previous conflict only as historical evidence. A
            # future status check must never mine this original transaction
            # automatically after a different payment has replaced its input.
            if "status_reason" in status:
                entry["status_reason"] = status["status_reason"]
            if "confirmed_nodes" in status:
                entry["confirmed_nodes"] = status["confirmed_nodes"]
        _record(entry)
        if entry != previous:
            self._touch(entry)
            self._write(document)

    def close(self):
        if self._closed:
            return
        self._closed = True
        for name in ("_lock_fd", "_directory_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                setattr(self, name, None)
                os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

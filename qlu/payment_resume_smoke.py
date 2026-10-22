#!/usr/bin/env python3
"""Exact-payment resume with real worker death and fresh private-node fixtures.

Credentials travel only through anonymous pipes. A deliberately crashed worker
leaves its laboratory nodes behind; the parent verifies their recorded ownership
and stops only those fixture nodes before launching the next worker. This is not
a claim that the production app automatically adopts orphaned nodes.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
from lab import private_port_lock
import protocol
import recovery
import vault
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork, _AppNet, address_script
from test_framework.messages import CTransaction, from_hex

LABEL = 'QLUWalletAppResume'


def fixture_identifier(value):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{32}', value) is None:
        raise ValueError('Invalid resume fixture identifier')
    return value


def fixture_paths(identifier):
    identifier = fixture_identifier(identifier)
    return (protocol.ROOT / '.local' / ('wallet-app-resume-' + identifier),
            'wallet-app-resume-net-' + identifier)


def ports_free():
    result = {}
    for port in (*range(28440, 28444), *range(28540, 28544)):
        with socket.socket() as client:
            result[str(port)] = client.connect_ex(('127.0.0.1', port)) != 0
    return result


def worker():
    if not __debug__:
        raise RuntimeError('This assertion-based private drill refuses optimized Python')
    setup = json.loads(sys.stdin.readline(4096))
    assert type(setup) is dict and set(setup) == {'identifier'}
    app_dir, data_name = fixture_paths(setup['identifier'])
    network = WalletAppNetwork(root=protocol.ROOT, data_name=data_name, process_label=LABEL)
    app = WalletApp(root=protocol.ROOT, network=network, app_dir=app_dir)
    def interrupted(signum, frame):
        raise SystemExit(1)
    signal.signal(signal.SIGTERM, interrupted)
    def emit(value):
        print(json.dumps(value, separators=(',', ':')), flush=True)
    try:
        emit({'ready': True})
        for line in sys.stdin:
            assert len(line) <= 65536
            packet = json.loads(line)
            if 'control' in packet:
                control = packet['control']
                if control == 'snapshot':
                    rows = app.history.records()
                    result = []
                    for row in rows:
                        public = {key: value for key, value in row.items()
                                  if key not in {'signed_transaction', 'transaction', 'spent_outputs'}}
                        if 'signed_transaction' in row:
                            public['signed_sha256'] = hashlib.sha256(bytes.fromhex(row['signed_transaction'])).hexdigest()
                        result.append(public)
                    emit({'records': result, 'height': network.controller.rpc(0, 'getblockcount')})
                elif control == 'recipient':
                    keys = protocol.keytool(recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS))
                    emit({'address': protocol.address_for(keys)})
                elif control == 'balance':
                    balance = network.balance(address_script(packet['address']))
                    emit({key: balance[key] for key in ('balance', 'immature_balance')})
                elif control == 'pooled':
                    emit({'pooled': [packet['txid'] in network.controller.rpc(i, 'getrawmempool') for i in range(4)]})
                elif control == 'expire_review':
                    # Test-only clock advancement of this one in-memory preview.
                    assert app._preview is not None
                    app._preview['deadline'] = time.monotonic() - 1
                    emit({'expired': True})
                elif control == 'offline':
                    entry = network.controller.read_state()['3']
                    assert network.controller.owned(3, entry)
                    network.controller.verify_node(3)
                    network.controller.rpc(3, 'stop')
                    deadline = time.monotonic() + 20
                    while network.controller.owned(3, entry):
                        assert time.monotonic() < deadline
                        time.sleep(.05)
                    emit({'stopped_owned_node': 3})
                elif control in ('invalidate', 'reconsider'):
                    method = 'invalidateblock' if control == 'invalidate' else 'reconsiderblock'
                    for i in range(4):
                        network.controller.rpc(i, method, packet['block'])
                    emit({'tip': network.controller.wait_synced()})
                elif control == 'rival':
                    # Deliberate adversarial fixture, bypassing the app's pending
                    # gate only to produce an independently valid competing spend.
                    prepared = network.prepare(app.keys, packet['recipient'], '0.20000000')
                    signed = app.session.sign(prepared.tx, list(prepared.spent))
                    raw = signed.serialize_with_witness().hex()
                    txid = network.controller.rpc(0, 'sendrawtransaction', raw)
                    block = network.controller.rpc(0, 'generateblock', packet['recipient'], [raw])['hash']
                    network.controller.wait_synced(block)
                    emit({'txid': txid, 'block': block})
                else:
                    raise ValueError('Unknown fixture control')
                continue
            guard, fault = packet.get('guard', 'allow'), packet.get('fault', '')
            assert guard in ('allow', 'resume', 'read_only')
            assert fault in ('', 'before_broadcast_exit', 'accepted_exit', 'accepted_timeout', 'before_resume_rpc_exit')
            calls = {'wallet_sign': 0, 'protocol_sign': 0, 'broadcast': 0, 'mine': 0}
            raw_hashes = []
            original_rpc, original_sign = network.controller.rpc, vault.WalletSession.sign
            original_protocol = protocol.sign_transaction
            def wallet_sign(session, *args, **kwargs):
                calls['wallet_sign'] += 1
                assert guard == 'allow', 'Resume must not sign'
                return original_sign(session, *args, **kwargs)
            def protocol_sign(*args, **kwargs):
                calls['protocol_sign'] += 1
                assert guard == 'allow', 'Resume must not sign'
                return original_protocol(*args, **kwargs)
            def rpc(index, method, *args, **kwargs):
                if method == 'sendrawtransaction':
                    digest = hashlib.sha256(bytes.fromhex(args[0])).hexdigest()
                    if fault == 'before_resume_rpc_exit':
                        emit({'event': fault, 'calls': calls, 'signed_sha256': digest})
                        os._exit(43)
                    assert guard != 'read_only', 'Status must not rebroadcast'
                    calls['broadcast'] += 1
                    raw_hashes.append(digest)
                if method in ('generateblock', 'generatetoaddress'):
                    calls['mine'] += 1
                    assert guard != 'read_only', 'Read-only checks must not mine'
                result = original_rpc(index, method, *args, **kwargs)
                if method == 'sendrawtransaction' and fault == 'accepted_exit':
                    emit({'event': fault, 'calls': calls, 'signed_sha256': raw_hashes[-1], 'txid': result})
                    os._exit(42)
                if method == 'sendrawtransaction' and fault == 'accepted_timeout':
                    raise TimeoutError('Synthetic accepted-response loss')
                return result
            if fault == 'before_broadcast_exit':
                durable = app.history.before_broadcast
                def before(operation, metadata):
                    durable(operation, metadata)
                    emit({'event': fault, 'calls': calls, 'txid': metadata['txid'],
                          'signed_sha256': hashlib.sha256(bytes.fromhex(metadata['signed_transaction'])).hexdigest()})
                    os._exit(41)
            else:
                before = None
            with patch.object(vault.WalletSession, 'sign', wallet_sign), \
                    patch.object(protocol, 'sign_transaction', protocol_sign), \
                    patch.object(network.controller, 'rpc', side_effect=rpc):
                if before is not None:
                    with patch.object(app.history, 'before_broadcast', side_effect=before):
                        response = app.handle(packet['request'])
                else:
                    response = app.handle(packet['request'])
            # Internal journal payloads must never appear in bridge responses.
            assert all(name not in json.dumps(response) for name in ('signed_transaction', 'spent_outputs'))
            emit({'response': response, 'calls': calls, 'raw_hashes': raw_hashes})
            if app.closed:
                break
    finally:
        app.close()


class Worker:
    def __init__(self, identifier):
        self.identifier = fixture_identifier(identifier)
        self.counter = 0
        self.last_operation = None
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, cwd=protocol.ROOT)
        self.process.stdin.write(json.dumps({'identifier': identifier}) + '\n')
        self.process.stdin.flush()
        try:
            assert self.read() == {'ready': True}
        except BaseException:
            self.close()
            raise

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(150):
                raise TimeoutError('Fixture worker did not respond')
        line = self.process.stdout.readline(1_048_576)
        if not line or len(line) >= 1_048_576:
            raise RuntimeError('Fixture worker response unavailable')
        return json.loads(line)

    def packet(self, value):
        self.process.stdin.write(json.dumps(value) + '\n')
        self.process.stdin.flush()
        return self.read()

    def control(self, control, **values):
        return self.packet({'control': control, **values})

    def request(self, command, params=None, *, guard='allow', fault='', error=None):
        self.counter += 1
        self.last_operation = {'command': command, 'error_code': None}
        result = self.packet({'guard': guard, 'fault': fault,
                              'request': {'id': self.counter, 'command': command, 'params': params or {}}})
        if 'event' in result:
            assert result['event'] == fault
            self.process.wait(timeout=10)
            assert self.process.returncode == {'before_broadcast_exit': 41, 'accepted_exit': 42,
                                              'before_resume_rpc_exit': 43}[fault]
            return result
        response = result['response']
        self.last_operation['error_code'] = response.get('error', {}).get('code')
        if guard != 'allow':
            assert result['calls']['wallet_sign'] == result['calls']['protocol_sign'] == 0
        if guard == 'read_only':
            assert result['calls']['broadcast'] == result['calls']['mine'] == 0
        if error is not None:
            assert response.get('ok') is False and response['error']['code'] == error, command
            if error != 'payment_pending':
                assert result['calls']['broadcast'] == result['calls']['mine'] == 0
        else:
            assert response.get('ok') is True, command
        return result

    def result(self, command, params=None, **options):
        response = self.request(command, params, **options)['response']
        return response['error'] if options.get('error') is not None else response['result']

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()
        # An os._exit checkpoint deliberately bypasses worker finally cleanup.
        # Reacquire the lab lease and match exact PID/token/data path before stop.
        with private_port_lock(protocol.ROOT):
            _, data_name = fixture_paths(self.identifier)
            controller = _AppNet(protocol.ROOT, data_name, LABEL)
            controller.stop()
            assert all(row['status'] == 'stopped' for row in controller.status())


class Fixture:
    def __init__(self, directory):
        self.identifier = uuid.uuid4().hex
        self.password = secrets.token_urlsafe(32)
        self.workers = []
        try:
            self.setup(directory)
        except BaseException:
            self.close()
            raise

    def setup(self, directory):
        self.worker = self.start()
        state = self.worker.result('create', {'passphrase': self.password, 'confirmation': self.password})
        self.path = state['wallet_path']
        backup = directory / (self.identifier + '-backup.json')
        code = self.worker.result('backup_create', {'backup_path': str(backup)})['code']
        state = self.worker.result('backup_verify', {'backup_path': str(backup), 'code': code})
        self.address = state['address']
        self.worker.result('network_start')
        self.funding = self.worker.result('faucet', {'operation_id': uuid.uuid4().hex})['payment']
        self.recipient = self.worker.control('recipient')['address']

    def start(self):
        value = Worker(self.identifier)
        self.workers.append(value)
        return value

    def restart(self):
        self.worker.close()
        self.worker = self.start()
        self.worker.result('open', {'path': self.path}, guard='read_only')
        self.worker.result('unlock', {'passphrase': self.password}, guard='read_only')
        return self.worker.result('network_start', guard='read_only')

    def pending(self, fault='before_broadcast_exit'):
        preview = self.worker.result('prepare_send', {'recipient': self.recipient, 'amount': '0.10000000'})
        self.operation = preview['preview_id']
        event = self.worker.request('confirm_send', {'preview_id': self.operation}, fault=fault)
        assert event['calls']['wallet_sign'] == 1
        self.txid, self.signed_hash = event['txid'], event['signed_sha256']
        return event

    def snapshot(self):
        value = self.worker.control('snapshot')
        record = next(row for row in value['records'] if row['operation_id'] == self.operation)
        assert record['txid'] == self.txid and record.get('signed_sha256') == self.signed_hash
        return value, record

    def review(self):
        value = self.worker.result('prepare_resume', {'operation_id': self.operation}, guard='read_only')
        assert value['operation_id'] == self.operation and value['txid'] == self.txid
        assert value['recipient'] == self.recipient and value['amount'] == '0.10000000' and value['fee'] == '0.00100000'
        return value

    def confirm(self, review, **options):
        return self.worker.request('confirm_resume', {'resume_id': review['resume_id']}, guard='resume', **options)

    def confirmed(self):
        value, row = self.snapshot()
        assert row['status'] == 'confirmed' and len(value['records']) == 2
        assert row['amount'] == '0.10000000' and row['fee'] == '0.00100000'
        assert self.worker.result('refresh', guard='read_only')['balance'] == '0.89900000'
        assert self.worker.control('balance', address=self.recipient)['balance'] == '0.10000000'
        replay = self.worker.result('confirm_send', {'preview_id': self.operation}, guard='read_only')
        assert replay['payment']['txid'] == self.txid
        assert self.worker.control('snapshot')['height'] == value['height']

    def wait_pooled(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if all(self.worker.control('pooled', txid=self.txid)['pooled']):
                return
            time.sleep(.1)
        raise AssertionError('Existing transaction did not reach all fixture mempools')

    def close(self):
        for worker in reversed(self.workers):
            worker.close()


def mutate_fixture_history(identifier, operation, mode):
    """Deliberately corrupt only a stopped fresh fixture's private journal."""
    app_dir, _ = fixture_paths(identifier)
    fixture_identifier(operation)
    if mode not in {'raw', 'amount', 'signature', 'legacy'}:
        raise ValueError('Invalid fixture mutation')
    folder = app_dir / 'payment-history'
    # Never follow a replacement link out of this exact fixture namespace.
    for parent in (app_dir.parent, app_dir, folder):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError('Invalid fixture directory')
    paths = list(folder.glob('*.json'))
    if len(paths) != 1 or re.fullmatch(r'[0-9a-f]{64}\.json', paths[0].name) is None:
        raise ValueError('Invalid fixture journal selection')
    path = paths[0]
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError('Invalid fixture journal file')
    data = json.loads(path.read_bytes())
    matches = [row for row in data['records'] if row['operation_id'] == operation]
    if len(matches) != 1 or matches[0]['status'] != 'pending':
        raise ValueError('Invalid fixture operation')
    row = matches[0]
    if mode == 'raw':
        row['signed_transaction'] += '00'
    elif mode == 'amount':
        row['amount'] = '0.20000000'
    elif mode == 'signature':
        tx = from_hex(CTransaction(), row['signed_transaction'])
        signature = bytearray(tx.wit.vtxinwit[0].scriptWitness.stack[2])
        signature[0] ^= 1
        tx.wit.vtxinwit[0].scriptWitness.stack[2] = bytes(signature)
        row['signed_transaction'] = tx.serialize_with_witness().hex()
    else:
        for entry in data['records']:
            entry.pop('signed_transaction', None)
            entry.pop('spent_outputs', None)
        data['version'] = 3
    # Test-only corruption after all worker ownership has been released.
    with path.open('w') as output:
        json.dump(data, output, sort_keys=True, separators=(',', ':'))
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def run():
    if not __debug__:
        raise RuntimeError('This assertion-based private drill refuses optimized Python')
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / '.local/payment-resume-drills'
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    hashes = lambda: {str(path.relative_to(protocol.ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in sorted((protocol.ROOT / 'qlu').glob('*.py'))}
    binaries = lambda: {name: hashlib.sha256((protocol.ROOT / 'build/qlu-foundation/bin' / name).read_bytes()).hexdigest()
                        for name in ('bitcoind', 'bitcoin-cli', 'qlu-keytool')}
    report = {'attempt': identifier, 'started_at': datetime.now(timezone.utc).isoformat(),
              'passed': False, 'checks': {}, 'observations': {},
              'source_sha256_at_start': hashes(), 'binary_sha256_at_start': binaries(),
              'scope': 'Fresh valueless four-node fixtures on one Mac; actual worker process exits and fixture-only journal corruption. No user wallet or native UI access.'}
    fixtures = []
    active = None
    def fresh():
        nonlocal active
        if active is not None:
            active.close()
        assert all(ports_free().values())
        active = Fixture(directory)
        fixtures.append(active)
        return active
    def passed(name):
        report['checks'][name] = True
        print(json.dumps({'check': name, 'passed': True}), flush=True)
    def resumed(fixture, review, **options):
        value = fixture.confirm(review, **options)
        assert value['response']['result']['payment']['txid'] == fixture.txid
        assert value['response']['result']['payment']['confirmed_nodes'] == 4
        assert all(item == fixture.signed_hash for item in value['raw_hashes'])
        assert value['calls']['mine'] == 1
        fixture.confirmed()
        return value
    try:
        assert all(ports_free().values()), 'Private ports already in use'
        f = fresh()
        event = f.pending()
        assert event['calls']['broadcast'] == event['calls']['mine'] == 0
        state = f.restart()
        value, row = f.snapshot()
        assert row['status'] == 'pending' and state['payment_blocked']
        assert not any(f.worker.control('pooled', txid=f.txid)['pooled'])
        f.worker.result('refresh', guard='read_only')
        passed('durable_before_broadcast_process_death_reopens_exact_pending_payment')

        review = f.review()
        f.worker.result('cancel_send', guard='read_only')
        f.confirm(review, error='resume_invalid')
        review = f.review()
        f.worker.control('expire_review')
        f.confirm(review, error='resume_invalid')
        review = f.review()
        f.worker.result('lock', guard='read_only')
        f.worker.result('unlock', {'passphrase': f.password}, guard='read_only')
        f.confirm(review, error='resume_invalid')
        assert f.snapshot()[1]['status'] == 'pending'
        passed('cancel_expiry_and_lock_invalidate_resume_review_without_signing_or_broadcast')

        f.worker.result('network_stop', guard='read_only')
        f.worker.result('prepare_resume', {'operation_id': f.operation}, guard='read_only', error='network_stopped')
        f.worker.result('network_start', guard='read_only')
        review = f.review()
        f.worker.control('offline')
        f.confirm(review, error='resume_unavailable')
        f.worker.result('network_stop', guard='read_only')
        f.worker.result('network_start', guard='read_only')
        passed('stopped_network_and_one_offline_node_refuse_resume')

        review = f.review()
        f.worker.control('invalidate', block=f.funding['block'])
        f.confirm(review, error='resume_unavailable')
        assert not any(f.worker.control('pooled', txid=f.txid)['pooled'])
        f.worker.control('reconsider', block=f.funding['block'])
        f.worker.result('refresh', guard='read_only')
        passed('reorg_after_review_refuses_saved_authorization_before_broadcast')

        review = f.review()
        event = f.confirm(review, fault='before_resume_rpc_exit')
        assert event['signed_sha256'] == f.signed_hash
        assert event['calls'] == {'wallet_sign': 0, 'protocol_sign': 0, 'broadcast': 0, 'mine': 0}
        f.restart()
        assert f.snapshot()[1]['status'] == 'pending'
        assert not any(f.worker.control('pooled', txid=f.txid)['pooled'])
        passed('process_death_during_resume_before_rpc_keeps_original_payment_pending')

        event = f.confirm(f.review(), fault='accepted_exit')
        assert event['txid'] == f.txid and event['signed_sha256'] == f.signed_hash
        assert event['calls']['wallet_sign'] == event['calls']['protocol_sign'] == 0
        assert event['calls']['broadcast'] == 1 and event['calls']['mine'] == 0
        f.restart()
        # A restored mempool may hold the original only on the accepting node.
        # Peer re-announcement after restart is not a prerequisite for recovery.
        pooled = f.worker.control('pooled', txid=f.txid)['pooled']
        assert pooled[0], 'Accepting node must retain the original transaction'
        review = f.review()
        answer = resumed(f, review)
        assert answer['calls']['broadcast'] <= 3
        f.confirm(review, error='resume_invalid')
        before = f.snapshot()[0]
        f.restart()
        f.confirmed()
        assert f.snapshot()[0] == before
        report['observations']['resumed_after_two_crashes'] = {
            'txid': f.txid, 'signed_sha256': f.signed_hash, 'final_calls': answer['calls'],
            'pooled_after_restart': pooled,
            'history_records': 2, 'sender_balance': '0.89900000', 'recipient_balance': '0.10000000'}
        passed('accepted_resume_then_process_death_finishes_same_pooled_transaction_once')

        f = fresh()
        event = f.pending('accepted_exit')
        assert event['calls']['broadcast'] == 1 and event['calls']['mine'] == 0
        f.restart()
        assert f.worker.control('pooled', txid=f.txid)['pooled'][0]
        answer = resumed(f, f.review())
        assert answer['calls']['broadcast'] <= 3
        passed('original_send_response_loss_survives_real_process_restart_without_resigning')

        f = fresh()
        f.pending()
        f.restart()
        answer = resumed(f, f.review(), fault='accepted_timeout')
        assert answer['calls']['broadcast'] >= 1
        report['observations']['accepted_response_timeout'] = {
            'txid': f.txid, 'signed_sha256': f.signed_hash, 'calls': answer['calls'],
            'all_broadcasts_exact_saved_bytes': True}
        passed('accepted_rpc_timeout_is_reconciled_from_exact_node_bytes_without_duplicate_fee')

        for mode in ('raw', 'amount'):
            f = fresh()
            f.pending()
            f.worker.close()
            mutate_fixture_history(f.identifier, f.operation, mode)
            f.worker = f.start()
            f.worker.result('open', {'path': f.path}, guard='read_only')
            f.worker.result('unlock', {'passphrase': f.password}, guard='read_only', error='history_unavailable')
            state = f.worker.result('status', guard='read_only')
            assert state['locked'] and not state['history_loaded']
            passed('corrupt_' + mode + '_fails_closed_on_new_process_unlock')

        f = fresh()
        f.pending()
        f.worker.close()
        mutate_fixture_history(f.identifier, f.operation, 'signature')
        f.restart()
        f.worker.result('prepare_resume', {'operation_id': f.operation}, guard='read_only', error='stale_payment')
        assert not any(f.worker.control('pooled', txid=f.txid)['pooled'])
        passed('canonical_but_invalid_signature_fails_all_node_preflight_without_broadcast')

        f = fresh()
        f.pending()
        f.worker.close()
        mutate_fixture_history(f.identifier, f.operation, 'legacy')
        state = f.restart()
        assert state['payment_blocked']
        f.worker.result('prepare_resume', {'operation_id': f.operation}, guard='read_only', error='resume_unavailable')
        rows = f.worker.control('snapshot')['records']
        row = next(item for item in rows if item['operation_id'] == f.operation)
        assert row['status'] == 'pending' and 'signed_sha256' not in row
        passed('legacy_pending_record_without_signed_bytes_remains_blocked_and_is_never_recreated')

        f = fresh()
        f.pending()
        f.restart()
        rival = f.worker.control('rival', recipient=f.recipient)
        state = f.worker.result('refresh', guard='read_only')
        assert not state['payment_blocked'] and f.snapshot()[1]['status'] == 'conflicted'
        f.worker.result('prepare_resume', {'operation_id': f.operation}, guard='read_only', error='resume_unavailable')
        f.worker.control('invalidate', block=rival['block'])
        state = f.worker.result('refresh', guard='read_only')
        row = f.snapshot()[1]
        assert state['payment_blocked'] and row['status'] == 'pending' and 'conflict' in row
        f.worker.result('prepare_resume', {'operation_id': f.operation}, guard='read_only', error='resume_unavailable')
        f.worker.control('reconsider', block=rival['block'])
        f.worker.result('refresh', guard='read_only')
        assert f.snapshot()[1]['status'] == 'conflicted'
        passed('active_and_reorged_historical_conflict_both_refuse_resume')
        report['passed'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__
        report['error_frames'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)]
        if active is not None:
            report['last_operation'] = active.worker.last_operation
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            report['interrupted'] = True
    finally:
        cleanup_errors = []
        for fixture in reversed(fixtures):
            try:
                fixture.close()
            except BaseException as error:
                cleanup_errors.append({'fixture': fixture.identifier, 'error_type': type(error).__name__})
        report['cleanup_errors'] = cleanup_errors
        report['workers'] = [{'fixture': fixture.identifier, 'pid': worker.process.pid,
                              'returncode': worker.process.poll()}
                             for fixture in fixtures for worker in fixture.workers]
        report['all_workers_reaped'] = all(row['returncode'] is not None for row in report['workers'])
        report['final_ports_free'] = ports_free()
        report['source_sha256_at_end'] = hashes()
        report['binary_sha256_at_end'] = binaries()
        report['source_unchanged'] = report['source_sha256_at_start'] == report['source_sha256_at_end']
        report['binaries_unchanged'] = report['binary_sha256_at_start'] == report['binary_sha256_at_end']
        report['passed'] &= (not cleanup_errors and report['all_workers_reaped']
                             and all(report['final_ports_free'].values()) and report['source_unchanged']
                             and report['binaries_unchanged'])
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        report['report_path'] = str(directory / 'result.json')
        target = directory / 'result.json'
        with target.open('x') as output:
            os.chmod(target, 0o600)
            json.dump(report, output, indent=2)
            output.write('\n')
    return report


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        worker()
    else:
        try:
            result = run()
            print(json.dumps(result, indent=2))
            raise SystemExit(0 if result['passed'] else 1)
        except Exception:
            print('QLU payment-resume drill failed; inspect its public evidence report.', file=sys.stderr)
            raise SystemExit(1)

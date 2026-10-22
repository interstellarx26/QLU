#!/usr/bin/env python3
"""Fresh-wallet identity isolation and real cross-process journal-lock drill.

Only newly created UUID fixtures are touched. Wallet replacement here is an
intentional test action, never a repair mechanism for a user's encrypted vault.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import subprocess
import sys
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
from payment_history import HistoryError, PaymentHistory
import protocol
import vault
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork


class StopBeforeBroadcast(BaseException):
    pass


def worker_setup(value):
    if (type(value) is not dict or set(value) != {'identifier', 'wallet_id', 'action'}
            or type(value['identifier']) is not str
            or re.fullmatch(r'[0-9a-f]{32}', value['identifier']) is None
            or type(value['wallet_id']) is not str
            or re.fullmatch(r'[0-9a-f]{64}', value['wallet_id']) is None
            or value['action'] not in ('probe', 'hold')):
        raise ValueError('Invalid fixture worker setup')
    return value


def journal_worker():
    if not __debug__:
        raise RuntimeError('This assertion-based private drill refuses optimized Python')
    setup = worker_setup(json.loads(sys.stdin.readline(4096)))
    directory = protocol.ROOT / '.local' / ('wallet-app-identity-' + setup['identifier']) / 'payment-history'
    # Workers may open an existing fixture only, never create missing app data.
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('Fixture journal directory is unavailable')
    store = None
    try:
        try:
            store = PaymentHistory(directory, setup['wallet_id'])
        except HistoryError:
            print(json.dumps({'acquired': False}), flush=True)
            return
        rows = store.records()
        print(json.dumps({'acquired': True, 'blocked': store.blocked,
                          'operations': [row['operation_id'] for row in rows]}), flush=True)
        if setup['action'] == 'hold':
            # A pipe rendezvous permits deterministic parent checks and an
            # actual abrupt death while this child still owns flock.
            sys.stdin.readline(32)
    finally:
        if store is not None:
            store.close()


class JournalWorker:
    def __init__(self, identifier, wallet_id, action):
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--journal-worker'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, cwd=protocol.ROOT)
        self.process.stdin.write(json.dumps(worker_setup(
            {'identifier': identifier, 'wallet_id': wallet_id, 'action': action})) + '\n')
        self.process.stdin.flush()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                if not selector.select(15):
                    raise RuntimeError('Fixture journal worker did not respond')
            self.response = json.loads(self.process.stdout.readline(65536))
        except BaseException:
            self.close()
            raise

    def kill(self):
        assert self.process.poll() is None
        self.process.kill()  # Only this exact Popen child; it owns no nodes.
        self.process.wait(timeout=10)
        assert self.process.returncode == -9

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write('close\n')
                self.process.stdin.flush()
                self.process.wait(timeout=10)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()


def replace_fixture_vault(path, blob, app_dir):
    """Replace only a generated fixture wallet, using a complete encrypted blob."""
    path, app_dir = Path(path), Path(app_dir)
    if (app_dir.parent != protocol.ROOT / '.local'
            or re.fullmatch(r'wallet-app-identity-[0-9a-f]{32}', app_dir.name) is None
            or path.parent != app_dir / 'wallets'
            or re.fullmatch(r'[0-9a-f]{32}\.vault\.json', path.name) is None
            or path.is_symlink() or not path.is_file()):
        raise ValueError('Replacement must stay in this identity fixture')
    temporary = path.with_name(uuid.uuid4().hex + '.fixture-replacement')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def ports_free():
    result = {}
    for port in (*range(28440, 28444), *range(28540, 28544)):
        with socket.socket() as client:
            result[str(port)] = client.connect_ex(('127.0.0.1', port)) != 0
    return result


def run():
    if not __debug__:
        raise RuntimeError('This assertion-based private drill refuses optimized Python')
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / '.local/wallet-identity-drills'
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    app_dir = protocol.ROOT / '.local' / ('wallet-app-identity-' + identifier)
    network = WalletAppNetwork(root=protocol.ROOT, data_name='wallet-app-identity-net-' + identifier,
                               process_label='QLUWalletAppIdentity')
    app = WalletApp(root=protocol.ROOT, network=network, app_dir=app_dir)
    workers = []
    names = ('wallet_identity_smoke.py', 'wallet_app.py', 'vault.py', 'payment_history.py',
             'wallet_app_network.py', 'payment_conflicts.py', 'backup_verification.py',
             'recovery.py', 'protocol.py', 'devnet.py', 'private_net.py')
    hashes = lambda: {name: hashlib.sha256((protocol.ROOT / 'qlu' / name).read_bytes()).hexdigest() for name in names}
    binaries = lambda: {name: hashlib.sha256((protocol.ROOT / 'build/qlu-foundation/bin' / name).read_bytes()).hexdigest()
                        for name in ('bitcoind', 'bitcoin-cli', 'qlu-keytool')}
    report = {'attempt': identifier, 'started_at': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'checks': {}, 'source_sha256_at_start': hashes(), 'binary_sha256_at_start': binaries(),
              'scope': 'Fresh A/B encrypted fixtures and four loopback nodes on one Mac. Intentional fixture file replacement and actual journal-lock worker death. No user files, native UI, public network, or power-loss durability claim.'}
    counter = 0
    last_operation = {}

    def request(command, params=None, *, error=None):
        nonlocal counter, last_operation
        counter += 1
        value = app.handle({'id': counter, 'command': command, 'params': params or {}})
        last_operation = {'command': command, 'error_code': value.get('error', {}).get('code')}
        if error is not None:
            assert value.get('ok') is False and value['error']['code'] == error, command
            return value['error']
        assert value.get('ok') is True, command
        return value['result']

    def create(label, password):
        state = request('create', {'passphrase': password, 'confirmation': password})
        path = Path(state['wallet_path'])
        backup = directory / (label + '-backup.json')
        code = request('backup_create', {'backup_path': str(backup)})['code']
        state = request('backup_verify', {'backup_path': str(backup), 'code': code})
        return {'path': path, 'address': state['address'], 'wallet_id': app.keys['key_commitment'],
                'blob': path.read_bytes(), 'backup': backup, 'code': code}

    def open_wallet(wallet, password, path=None):
        state = request('open', {'path': str(path or wallet['path'])})
        assert state['locked'] and state['address'] is None
        state = request('unlock', {'passphrase': password})
        assert state['address'] == wallet['address'] and app.history.wallet_id == wallet['wallet_id']
        return state

    def cleared():
        state = request('status')
        assert state['wallet_open'] is False and state['locked'] is True
        assert state['address'] is None and state['wallet_path'] is None
        assert not state['history_loaded'] and state['payment_history'] == []
        assert state['recent_payment'] is None and state['pending_payment'] is None
        assert state['balance'] is None and not state['network_healthy'] and not state['backup_verified']
        assert app.keys is None and app.session is None and app.history is None and app._preview is None

    try:
        assert all(ports_free().values())
        password = secrets.token_urlsafe(32)
        first = create('A', password)
        request('network_start')
        request('faucet', {'operation_id': uuid.uuid4().hex})
        second = create('B', password)
        assert first['wallet_id'] != second['wallet_id']
        open_wallet(first, password)
        preview = request('prepare_send', {'recipient': second['address'], 'amount': '0.10000000'})
        sent = request('confirm_send', {'preview_id': preview['preview_id']})['payment']
        assert request('refresh')['balance'] == '0.89900000'
        open_wallet(second, password)
        request('verify_received', {'txid': sent['txid']})
        assert request('refresh')['balance'] == '0.10000000'
        pending_preview = request('prepare_send', {'recipient': first['address'], 'amount': '0.01000000'})
        durable = app.history.before_broadcast
        def stop_after_record(operation, metadata):
            durable(operation, metadata)
            raise StopBeforeBroadcast()
        with patch.object(app.history, 'before_broadcast', side_effect=stop_after_record):
            try:
                request('confirm_send', {'preview_id': pending_preview['preview_id']})
            except StopBeforeBroadcast:
                pass
            else:
                raise AssertionError('Durable pending fixture boundary not reached')
        assert request('refresh')['payment_blocked']
        second_rows = app.history.records()
        pending = next(row for row in second_rows if row['operation_id'] == pending_preview['preview_id'])
        assert pending['status'] == 'pending' and pending['status_reason'] == 'not_found'
        assert all(pending['txid'] not in network.controller.rpc(i, 'getrawmempool') for i in range(4))
        open_wallet(first, password)
        assert request('refresh')['balance'] == '0.89900000'
        first_rows = app.history.records()
        paths = {value['wallet_id']: app_dir / 'payment-history' / (value['wallet_id'] + '.json')
                 for value in (first, second)}
        journals = {key: path.read_bytes() for key, path in paths.items()}
        def journals_unchanged():
            assert all(path.read_bytes() == journals[key] for key, path in paths.items())
        report['checks']['distinct_funded_wallets_have_separate_confirmed_and_pending_journals'] = True

        calls = {'sign': 0, 'broadcast_or_mine': 0}
        original_rpc = network.controller.rpc
        def no_sign(*args, **kwargs):
            calls['sign'] += 1
            raise AssertionError('Identity checks must not sign')
        def read_only(index, method, *args, **kwargs):
            if method in {'sendrawtransaction', 'generateblock', 'generatetoaddress'}:
                calls['broadcast_or_mine'] += 1
                raise AssertionError('Identity checks must not broadcast or mine')
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(vault.WalletSession, 'sign', side_effect=no_sign), \
                patch.object(network.controller, 'rpc', side_effect=read_only):
            preview = request('prepare_send', {'recipient': second['address'], 'amount': '0.02000000'})
            request('lock')
            replace_fixture_vault(first['path'], second['blob'], app_dir)
            request('unlock', {'passphrase': password}, error='wallet_changed')
            cleared()
            request('confirm_send', {'preview_id': preview['preview_id']}, error='no_wallet')
            journals_unchanged()
            report['checks']['locked_path_replacement_clears_identity_and_refuses_old_authorization'] = True

            state = open_wallet(second, password, first['path'])
            assert state['payment_blocked'] and app.history.records() == second_rows
            assert state['balance'] is None and not state['network_healthy']
            state = request('refresh')
            assert state['balance'] == '0.10000000' and state['payment_blocked']
            request('prepare_send', {'recipient': first['address'], 'amount': '0.01000000'}, error='payment_pending')
            journals_unchanged()
            report['checks']['explicit_reopen_adopts_only_B_identity_history_and_pending_guard'] = True

            request('lock')
            replace_fixture_vault(first['path'], first['blob'], app_dir)
            request('open', {'path': str(first['path'])})
            replace_fixture_vault(first['path'], second['blob'], app_dir)
            request('unlock', {'passphrase': password}, error='wallet_changed')
            cleared()
            journals_unchanged()
            report['checks']['replacement_after_open_before_first_unlock_is_refused'] = True

            replace_fixture_vault(first['path'], first['blob'], app_dir)
            open_wallet(first, password)
            request('lock')
            replace_fixture_vault(first['path'], first['blob'], app_dir)
            state = request('unlock', {'passphrase': password})
            assert state['address'] == first['address'] and app.history.records() == first_rows
            journals_unchanged()
            report['checks']['identical_encrypted_bytes_with_new_inode_preserve_identity'] = True

            restored = app_dir / 'wallets' / (uuid.uuid4().hex + '.vault.json')
            session = vault.WalletSession.restore(restored, first['backup'].read_bytes(), first['code'], password)
            try:
                assert session.public_keys()['key_commitment'] == first['wallet_id']
            finally:
                session.lock()
            restored_blob = restored.read_bytes()
            assert restored_blob != first['blob']
            request('lock')
            replace_fixture_vault(first['path'], restored_blob, app_dir)
            request('unlock', {'passphrase': password}, error='wallet_changed')
            cleared()
            request('open', {'path': str(restored)})
            state = request('unlock', {'passphrase': password})
            assert app.keys['key_commitment'] == first['wallet_id'] and app.history.records() == first_rows
            assert not state['backup_verified'] and state['backup_verification_status'] == 'required'
            request('prepare_send', {'recipient': second['address'], 'amount': '0.02000000'}, error='backup_required')
            journals_unchanged()
            report['checks']['same_keys_in_changed_ciphertext_still_require_explicit_open'] = True

            replace_fixture_vault(first['path'], first['blob'], app_dir)
            open_wallet(first, password)
            assert request('refresh')['balance'] == '0.89900000'
            request('lock')
            request('unlock', {'passphrase': 'Incorrect synthetic fixture passphrase'}, error='wallet_failed')
            state = request('status')
            assert state['wallet_open'] and state['locked'] and state['address'] is None
            assert not state['history_loaded'] and state['recent_payment'] is None
            assert state['balance'] is None and not state['backup_verified'] and not state['network_healthy']
            state = request('unlock', {'passphrase': password})
            assert state['address'] == first['address'] and app.history.records() == first_rows
            journals_unchanged()
            report['checks']['wrong_passphrase_clears_authenticated_state_and_correct_retry_recovers_A'] = True

            open_wallet(second, password)
            probe = JournalWorker(identifier, second['wallet_id'], 'probe')
            workers.append(probe)
            assert probe.response == {'acquired': False}
            probe.close()
            assert probe.process.returncode == 0
            journals_unchanged()
            report['checks']['competing_process_cannot_open_owned_wallet_journal'] = True

            open_wallet(first, password)
            holder = JournalWorker(identifier, second['wallet_id'], 'hold')
            workers.append(holder)
            assert holder.response['acquired'] is True and holder.response['blocked'] is True
            assert holder.response['operations'] == [row['operation_id'] for row in second_rows]
            request('open', {'path': str(second['path'])})
            request('unlock', {'passphrase': password}, error='history_unavailable')
            journals_unchanged()
            holder.kill()
            holder.close()
            state = open_wallet(second, password)
            assert state['payment_blocked'] and app.history.records() == second_rows
            request('prepare_send', {'recipient': first['address'], 'amount': '0.01000000'}, error='payment_pending')
            journals_unchanged()
            report['checks']['abrupt_competing_process_death_releases_lock_without_losing_B_pending_guard'] = True

            assert request('refresh')['balance'] == '0.10000000'
            open_wallet(first, password)
            assert request('refresh')['balance'] == '0.89900000'
            assert app.history.records() == first_rows and not app.state()['payment_blocked']
            journals_unchanged()
            assert first['path'].read_bytes() == first['blob'] and second['path'].read_bytes() == second['blob']
        assert calls == {'sign': 0, 'broadcast_or_mine': 0}
        report['checks']['all_identity_trials_preserve_both_journals_balances_and_zero_payment_side_effects'] = True
        report['guard_calls'] = calls
        report['journal_sha256'] = {key: hashlib.sha256(data).hexdigest() for key, data in journals.items()}
        report['worker_processes'] = len(workers)
        report['passed'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__
        report['error_location'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                                    for frame in traceback.extract_tb(error.__traceback__)]
        report['last_operation'] = last_operation
        raise
    finally:
        cleanup = True
        for worker in workers:
            try:
                worker.close()
            except BaseException:
                cleanup = False
        try:
            app.close()
        except BaseException:
            cleanup = False
        report['cleanup'] = 'owned-workers-and-nodes-stopped' if cleanup else 'needs-attention'
        report['ports_free'] = ports_free()
        report['source_sha256_at_end'] = hashes()
        report['source_unchanged'] = report['source_sha256_at_start'] == report['source_sha256_at_end']
        report['binary_sha256_at_end'] = binaries()
        report['binaries_unchanged'] = report['binary_sha256_at_start'] == report['binary_sha256_at_end']
        report['passed'] = report['passed'] and cleanup and all(report['ports_free'].values()) and report['source_unchanged'] and report['binaries_unchanged']
        report['completed_at'] = datetime.now(timezone.utc).isoformat()
        evidence = protocol.ROOT / '.local/evidence'
        secure_directory(evidence)
        for destination in (directory / 'result.json', evidence / 'wallet-identity-latest.json'):
            destination.write_text(json.dumps(report, indent=2) + '\n')
            destination.chmod(0o600)
    return report


if __name__ == '__main__':
    if sys.argv[1:] == ['--journal-worker']:
        journal_worker()
    else:
        try:
            result = run()
            print(json.dumps(result, indent=2))
            raise SystemExit(0 if result['passed'] else 1)
        except Exception:
            print('QLU wallet-identity drill failed; inspect its public evidence report.', file=sys.stderr)
            raise SystemExit(1)

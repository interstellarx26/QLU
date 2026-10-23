#!/usr/bin/env python3
"""Conflicting hybrid spends and actual 2+2 partitions on fresh private fixtures.

The drill-only -noconnect controller changes connectivity, never consensus. It
uses only the four owned loopback nodes and never opens a user wallet. Lab SHA-256
work and temporary regtest rewards are not production mining claims.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import DevnetError, RpcError, secure_directory
import protocol
import recovery
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork, _AppNet, NetworkError, format_amount
from payment_history import PaymentHistory
from test_framework.messages import CBlock, CBlockHeader, CTransaction, from_hex
from test_framework.blocktools import add_witness_commitment

GROUPS = ({0, 1}, {2, 3})


def failure_location(error):
    """No exception messages, source lines, local variables or absolute paths."""
    result = {'error_type': type(error).__name__,
              'error_location': [{'file': Path(frame.filename).name, 'line': frame.lineno,
                                  'function': frame.name}
                                 for frame in traceback.extract_tb(error.__traceback__)]}
    if isinstance(error, RpcError) and type(error.code) is int and -(2 ** 31) <= error.code < 2 ** 31:
        result['rpc_error_code'] = error.code
    return result


def failure_summary(report):
    """Explicit public allowlist; never publish arbitrary future report fields."""
    names = ('attempt', 'started_at', 'completed_at', 'passed', 'checks',
             'error_type', 'error_location', 'rpc_error_code', 'last_operations', 'controller_failures',
             'cleanup', 'ports_free', 'source_unchanged', 'binaries_unchanged')
    return {name: report[name] for name in names if name in report}


def share_known_losing_header(controller, losing_hash, losing_raw, winner_hash, losing_work, winning_work,
                              *, expected_parent, expected_height):
    """Make this drill's known losing header available before invalidating it.

    Normal peer synchronization need not distribute a lower-work branch. The
    header is captured on its producing node while that block is active.
    Importing it here must not change the already established winning chain.
    This establishes header knowledge, not full-block acceptance, and is fixture
    preparation rather than a wallet or consensus recovery mechanism.
    """
    assert type(losing_hash) is str and re.fullmatch(r'[0-9a-f]{64}', losing_hash)
    assert type(winner_hash) is str and re.fullmatch(r'[0-9a-f]{64}', winner_hash) and winner_hash != losing_hash
    assert type(expected_parent) is str and re.fullmatch(r'[0-9a-f]{64}', expected_parent)
    assert type(expected_height) is int and expected_height > 0
    assert type(losing_raw) is str and re.fullmatch(r'[0-9a-f]{160}', losing_raw)
    assert type(losing_work) is int and type(winning_work) is int and 0 < losing_work < winning_work
    header = from_hex(CBlockHeader(), losing_raw)
    assert header.hash_hex == losing_hash and header.serialize().hex() == losing_raw
    assert f'{header.hashPrevBlock:064x}' == expected_parent

    def check_winner(index):
        state = controller.rpc(index, 'getblockchaininfo')
        assert state['bestblockhash'] == winner_hash and int(state['chainwork'], 16) == winning_work

    for index in range(4):
        check_winner(index)
    observations = []
    for index in range(4):
        # bitcoin-cli prints no output for JSON null; this controller returns
        # the empty stdout string, rather than Python None, on success.
        assert controller.rpc(index, 'submitheader', losing_raw) == ''
        assert controller.rpc(index, 'getblockheader', losing_hash, False) == losing_raw
        header = controller.rpc(index, 'getblockheader', losing_hash)
        assert header['hash'] == losing_hash and header['confirmations'] == -1
        assert header['previousblockhash'] == expected_parent and header['height'] == expected_height
        assert int(header['chainwork'], 16) == losing_work
        check_winner(index)
        observations.append({'node': index, 'stored_header_verified': True, 'winning_tip_unchanged': True})
    for index in range(4):
        check_winner(index)
    return {'losing_block': losing_hash, 'winning_tip': winner_hash,
            'losing_chainwork': f'{losing_work:x}', 'winning_chainwork': f'{winning_work:x}',
            'raw_header_sha256': hashlib.sha256(bytes.fromhex(losing_raw)).hexdigest(), 'nodes': observations}


def identify_peers(peers, state, label, local, *, allow_incomplete=False):
    """Fail closed on non-loopback, foreign, ambiguous or malformed peer data."""
    result = {}
    for peer in peers:
        assert type(peer) is dict and type(peer.get('id')) is int
        address, subver = peer.get('addr'), peer.get('subver')
        assert type(address) is str and address.startswith('127.0.0.1:')
        assert address.rsplit(':', 1)[1].isdigit()
        if subver == '' and allow_incomplete:
            continue
        assert type(subver) is str and subver
        matches = [int(index) for index, entry in state.items()
                   if f"{label}-{entry['token']}" in subver]
        assert len(matches) == 1 and matches[0] != local
        result[peer['id']] = matches[0]
    return result


class PartitionController(_AppNet):
    """Only this UUID fixture uses manual owned-peer connections."""
    def __init__(self, root, data_name):
        super().__init__(root, data_name, 'QLUWalletAppResilience')
        self.children = {}
        self.start_failure = None

    def endpoint(self, index):
        assert type(index) is int and index in range(4)
        return f'127.0.0.1:{self.p2p_base + index}'

    def start_one(self, index):
        assert index in range(4)
        self.setup()
        self.require_binaries()
        state = self.read_state()
        previous = state.get(str(index))
        if previous is not None:
            assert not self.owned(index, previous) and not self.pid_command(previous['pid'])
        assert self.port_free(self.p2p_base + index) and self.port_free(self.rpc_base + index)
        token = uuid.uuid4().hex
        node = self.node(index)
        fd = os.open(node / 'resilience-startup.log', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'ab') as output:
            process = subprocess.Popen(
                [str(self.binary), f'-{self.chain}', '-nosettings', f'-datadir={node}',
                 f'-conf={node / "bitcoin.conf"}', '-daemon=0', '-noconnect',
                 f'-uacomment={self.process_label}-{token}'],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        self.children[index] = process
        entry = {'pid': process.pid, 'token': token}
        state[str(index)] = entry
        try:
            self.save_state(state)
        except BaseException:
            # A failed ownership-file write must not strand the direct child.
            # Match this launch's in-memory token before sending any signal.
            if process.poll() is None and self.owned(index, entry):
                process.terminate()
                process.wait(timeout=15)
            if process.poll() is None:
                raise DevnetError('Fresh fixture child cleanup could not be verified') from None
            self.children.pop(index, None)
            raise
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            assert process.poll() is None, 'Owned fixture node exited during startup'
            try:
                self.verify_node(index)
                return
            except RpcError:
                time.sleep(.1)
        raise AssertionError('Owned fixture node startup timeout')

    def start(self):
        self.setup()
        self.require_binaries()
        self.require_stopped()
        assert shutil.disk_usage(self.root).free >= 1024 ** 3
        try:
            for index in range(4):
                self.start_one(index)
            self.reconnect()
        except BaseException as error:
            # WalletApp deliberately translates backend errors. Retain only
            # their safe location here before that translation loses it.
            self.start_failure = failure_location(error)
            self.stop()
            raise

    def stop_one(self, index):
        entry = self.read_state()[str(index)]
        assert self.owned(index, entry)
        self.verify_node(index)
        self.rpc(index, 'stop')
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and self.owned(index, entry):
            time.sleep(.1)
        process = self.children.pop(index, None)
        if process is not None:
            process.wait(timeout=5)
        assert not self.pid_command(entry['pid'])
        assert self.port_free(self.p2p_base + index) and self.port_free(self.rpc_base + index)

    def stop(self):
        super().stop()
        for process in self.children.values():
            process.wait(timeout=5)
        self.children.clear()

    def reconnect(self):
        for index in range(4):
            added = {row['addednode'] for row in self.rpc(index, 'getaddednodeinfo')}
            assert added <= {self.endpoint(other) for other in range(4) if other != index}
            for other in range(4):
                if other != index and self.endpoint(other) not in added:
                    self.rpc(index, 'addnode', self.endpoint(other), 'add')
        # Core's persistent addnode retry sleeps up to 60 seconds after an
        # attempt. Explicit loopback onetry connections make this controlled
        # reconnection immediate, without loosening the handshake assertions.
        state = self.read_state()
        for index in range(4):
            connected = set(identify_peers(self.rpc(index, 'getpeerinfo'), state,
                                          self.process_label, index, allow_incomplete=True).values())
            for other in range(index + 1, 4):
                if other not in connected:
                    self.rpc(index, 'addnode', self.endpoint(other), 'onetry')
        self.wait_connected(self.read_state())
        self.wait_synced()

    def partition(self):
        state = self.read_state()
        for index in range(4):
            own_group = next(group for group in GROUPS if index in group)
            for other in set(range(4)) - own_group:
                self.rpc(index, 'addnode', self.endpoint(other), 'remove')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            separated = True
            for index in range(4):
                own_group = next(group for group in GROUPS if index in group)
                peers = self.rpc(index, 'getpeerinfo')
                known = identify_peers(peers, state, self.process_label, index, allow_incomplete=True)
                for peer_id, other in known.items():
                    if other not in own_group:
                        separated = False
                        try:
                            self.rpc(index, 'disconnectnode', '', peer_id)
                        except RpcError as error:
                            if error.code != -29:
                                raise
                if set(known.values()) != own_group - {index} or any(peer.get('subver') == '' for peer in peers):
                    separated = False
            # A pending connection can finish between this scan and its
            # confirming snapshot. Keep converging within the same deadline;
            # malformed, foreign and non-loopback identities still raise.
            if separated and self._partition_ready(allow_incomplete=True):
                return
            time.sleep(.1)
        raise AssertionError('Exact 2+2 partition was not established')

    def _partition_ready(self, *, allow_incomplete=False):
        state = self.read_state()
        ready = True
        for index in range(4):
            own_group = next(group for group in GROUPS if index in group)
            self.verify_node(index)
            peers = self.rpc(index, 'getpeerinfo')
            known = identify_peers(peers, state, self.process_label, index,
                                   allow_incomplete=allow_incomplete)
            if set(known.values()) != own_group - {index} or any(peer.get('subver') == '' for peer in peers):
                ready = False
        return ready

    def assert_partition(self):
        assert self._partition_ready()
        return True

    def group_synced(self, indexes, expected):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if all(self.rpc(index, 'getbestblockhash') == expected for index in indexes):
                return
            time.sleep(.1)
        raise AssertionError('Fixture group did not synchronize')


class FixtureWallet:
    def __init__(self, network, directory, label, restore=None):
        self.network = network
        self.app_dir = protocol.ROOT / '.local' / ('wallet-app-resilience-' + uuid.uuid4().hex)
        self.password = secrets.token_urlsafe(32)
        self.counter = 0
        self.last_command = self.last_error = None
        self.app = WalletApp(root=protocol.ROOT, network=network, app_dir=self.app_dir)
        phrase = {'passphrase': self.password, 'confirmation': self.password}
        if restore is None:
            self.request('create', phrase)
            self.backup = directory / (label + '-backup.json')
            self.code = self.request('backup_create', {'backup_path': str(self.backup)})['code']
            state = self.request('backup_verify', {'backup_path': str(self.backup), 'code': self.code})
        else:
            self.backup, self.code = restore.backup, restore.code
            state = self.request('restore', {**phrase, 'backup_path': str(self.backup), 'code': self.code})
        self.path, self.address = state['wallet_path'], state['address']

    def request(self, command, params=None, *, error=None):
        self.last_command = command
        self.counter += 1
        result = self.app.handle({'id': self.counter, 'command': command, 'params': params or {}})
        self.last_error = result.get('error', {}).get('code')
        if error is not None:
            assert result.get('ok') is False and self.last_error == error, command
            return result['error']
        assert result.get('ok') is True, command
        return result['result']

    def record(self, txid):
        return next(row for row in self.app.history.records() if row.get('txid') == txid)

    def prepare(self, recipient):
        preview = self.request('prepare_send', {'recipient': recipient, 'amount': '0.50000000'})
        prepared = self.app._preview['prepared']
        signed = self.app.session.sign(prepared.tx, list(prepared.spent))
        return preview, signed

    def authorize_fixture_branch(self, preview, signed, start_height):
        # Deliberate test-harness authorization of two conflicting alternatives,
        # on distinct restored app installations. Never bypass the wallet's gate
        # to claim that its normal UI would authorize a partitioned payment.
        operation = preview['preview_id']
        details = {key: preview[key] for key in ('recipient', 'amount', 'fee')}
        self.app.history.begin('send', operation_id=operation, **details)
        self.app.history.before_broadcast(operation, {**details, 'txid': signed.txid_hex,
                                                     'start_height': start_height,
                                                     'transaction': signed.serialize_without_witness().hex()})
        self.app._preview = None

    def reopen(self, network):
        self.network = network
        self.app = WalletApp(root=protocol.ROOT, network=network, app_dir=self.app_dir)
        self.request('open', {'path': self.path})
        state = self.request('unlock', {'passphrase': self.password})
        assert state['backup_verified'] and state['address'] == self.address


def ports_free():
    result = {}
    for port in (*range(28440, 28444), *range(28540, 28544)):
        with socket.socket() as client:
            result[str(port)] = client.connect_ex(('127.0.0.1', port)) != 0
    return result


def legacy_pending_history(directory, wallet, txid):
    """A separate valid v2 fixture proves absent metadata is never invented."""
    destination = directory / 'legacy-history'
    secure_directory(destination)
    record = wallet.record(txid)
    record = {key: value for key, value in record.items()
              if key not in {'transaction', 'conflict', 'block', 'confirmed_nodes', 'status_reason'}}
    record['status'] = 'pending'
    document = {**wallet.app.history._empty(), 'version': 2, 'records': [record]}
    wallet_id = wallet.app.history.wallet_id
    for name, data in ((wallet_id + '.lock', b''),
                       (wallet_id + '.json', (json.dumps(document) + '\n').encode())):
        fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    return PaymentHistory(destination, wallet_id)


def reopen_worker():
    """Reopen only explicitly named fresh fixture data, using secret pipes."""
    if not __debug__:
        raise RuntimeError('This assertion-based private drill refuses optimized Python')
    setup = json.loads(sys.stdin.readline(65536))
    app_name, data_name = setup['app_name'], setup['data_name']
    if (re.fullmatch(r'wallet-app-resilience-[0-9a-f]{32}', app_name) is None
            or re.fullmatch(r'wallet-app-resilience-net-[0-9a-f]{32}', data_name) is None):
        raise ValueError('Invalid fixture identity')
    app_dir = protocol.ROOT / '.local' / app_name
    path = Path(setup['wallet_path'])
    if not path.is_relative_to(app_dir / 'wallets'):
        raise ValueError('Fixture wallet path escapes its private app directory')
    network = WalletAppNetwork(root=protocol.ROOT, data_name=data_name, process_label='QLUWalletAppResilience')
    network.controller = PartitionController(protocol.ROOT, data_name)
    app = WalletApp(root=protocol.ROOT, network=network, app_dir=app_dir)
    def interrupt(signum, frame):
        raise SystemExit(1)
    signal.signal(signal.SIGTERM, interrupt)
    count = 0
    def request(command, params=None):
        nonlocal count
        count += 1
        return app.handle({'id': count, 'command': command, 'params': params or {}})
    try:
        assert request('open', {'path': str(path)})['ok']
        unlocked = request('unlock', {'passphrase': setup['passphrase']})
        assert unlocked['ok'] and unlocked['result']['backup_verified']
        state = request('network_start')
        assert state['ok']
        state = state['result']
        assert state['balance'] == setup['balance'] and state['payment_blocked'] is False
        rows = {row['txid']: row for row in app.history.records() if 'txid' in row}
        for txid, status in setup['statuses'].items():
            assert rows[txid]['status'] == status
        height = network.controller.rpc(0, 'getblockcount')
        original_rpc = network.controller.rpc
        calls = {'sign': 0, 'broadcast': 0}
        def no_sign(*args, **kwargs):
            calls['sign'] += 1
            raise AssertionError('Reopen must not sign')
        def no_broadcast(index, method, *args, **kwargs):
            if method in {'sendrawtransaction', 'generateblock'}:
                calls['broadcast'] += 1
                raise AssertionError('Reopen replay must not broadcast or mine')
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(app.session, 'sign', side_effect=no_sign), patch.object(network.controller, 'rpc', side_effect=no_broadcast):
            for replay in setup['replays']:
                value = request('confirm_send', {'preview_id': replay['operation_id']})
                if 'error' in replay:
                    assert not value['ok'] and value['error']['code'] == replay['error']
                else:
                    assert value['ok'] and value['result']['payment']['txid'] == replay['txid']
        assert calls == {'sign': 0, 'broadcast': 0}
        assert network.controller.rpc(0, 'getblockcount') == height
        print(json.dumps({'passed': True, 'guard': calls, 'balance': state['balance'],
                          'statuses': setup['statuses']}), flush=True)
    finally:
        app.close()


def probe_reopen(wallet, data_name, *, statuses, replays, balance):
    """Passphrase stays in an anonymous pipe; child output is public checks only."""
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--reopen-worker'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, cwd=protocol.ROOT)
    payload = {'app_name': wallet.app_dir.name, 'data_name': data_name, 'wallet_path': wallet.path,
               'passphrase': wallet.password, 'statuses': statuses, 'replays': replays, 'balance': balance}
    try:
        output, _ = process.communicate(json.dumps(payload) + '\n', timeout=150)
        assert process.returncode == 0 and json.loads(output)['passed'] is True
        return json.loads(output)
    except subprocess.TimeoutExpired:
        process.terminate()  # Its SIGTERM handler runs verified owned-node cleanup.
        try:
            process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()  # This direct child only; nodes are checked below.
            process.communicate(timeout=10)
        raise
    finally:
        if process.poll() is not None:
            # Covers startup or worker exceptions too; only this exact fixture
            # controller's recorded PID/token/data-directory identities qualify.
            PartitionController(protocol.ROOT, data_name).stop()


def run():
    if not __debug__:
        raise RuntimeError('This assertion-based private drill refuses optimized Python')
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / '.local/network-resilience-drills'
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    names = ('network_resilience_smoke.py', 'wallet_app_network.py', 'wallet_app.py', 'payment_history.py', 'payment_conflicts.py', 'protocol.py', 'devnet.py', 'private_net.py')
    hashes = lambda: {name: hashlib.sha256((protocol.ROOT / 'qlu' / name).read_bytes()).hexdigest() for name in names}
    binary_hashes = lambda: {name: hashlib.sha256((protocol.ROOT / 'build/qlu-foundation/bin' / name).read_bytes()).hexdigest()
                             for name in ('bitcoind', 'bitcoin-cli', 'qlu-keytool')}
    report = {'attempt': identifier, 'started_at': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'checks': {}, 'observations': {}, 'transactions': {}, 'source_sha256_at_start': hashes(),
              'binary_sha256_at_start': binary_hashes(),
              'scope': 'Fresh UUID wallets and four loopback nodes on one Mac. Actual hybrid conflicting spends and 2+2 partition. Temporary SHA-256 lab proof of work only; no user wallet, public network, native UI, or production consensus claim.'}
    wallets, networks, histories = [], [], []
    data_name = 'wallet-app-resilience-net-' + identifier

    def new_network():
        network = WalletAppNetwork(root=protocol.ROOT, data_name=data_name, process_label='QLUWalletAppResilience')
        network.controller = PartitionController(protocol.ROOT, data_name)
        networks.append(network)
        return network

    def common_utxos(controller, tip):
        rows = [controller.rpc(index, 'gettxoutsetinfo') for index in range(4)]
        assert all(row['bestblock'] == tip for row in rows)
        fingerprints = {(row['height'], row['bestblock'], row['txouts'], row['hash_serialized_3'], str(row['total_amount'])) for row in rows}
        assert len(fingerprints) == 1
        return rows[0]['hash_serialized_3']

    try:
        assert all(ports_free().values()), 'Private ports are not free'
        network = new_network()
        left = FixtureWallet(network, directory, 'left')
        wallets.append(left)
        right = FixtureWallet(network, directory, 'right', restore=left)
        wallets.append(right)
        assert left.address == right.address
        recipient_left = protocol.keytool(recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS))
        recipient_right = protocol.keytool(recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS))
        address_left, address_right = protocol.address_for(recipient_left), protocol.address_for(recipient_right)
        assert len({left.address, address_left, address_right}) == 3
        left.request('network_start')
        controller = network.controller
        funding = left.request('faucet', {'operation_id': uuid.uuid4().hex})['payment']
        assert right.request('refresh')['balance'] == '1.00000000'
        common_tip = controller.wait_synced()
        start_height = controller.rpc(0, 'getblockcount')
        preview = left.request('prepare_send', {'recipient': address_left, 'amount': '0.50000000'})
        report['checks']['fresh_four_node_hybrid_fixture_and_restored_copy_funded'] = True

        controller.partition()
        assert all(controller.rpc(index, 'getbestblockhash') == common_tip for index in range(4))
        assert left.app._preview['id'] == preview['preview_id'] and time.monotonic() < left.app._preview['deadline']
        original_rpc = controller.rpc
        blocked_calls = {'sign': 0, 'sendrawtransaction': 0}
        def no_broadcast(index, method, *args, **kwargs):
            if method == 'sendrawtransaction':
                blocked_calls[method] += 1
                raise AssertionError('Partition must not reach broadcast')
            return original_rpc(index, method, *args, **kwargs)
        def no_sign(*args, **kwargs):
            blocked_calls['sign'] += 1
            raise AssertionError('Partition must not reach signing')
        with patch.object(controller, 'rpc', side_effect=no_broadcast), patch.object(left.app.session, 'sign', side_effect=no_sign):
            try:
                network.prepare(left.app.keys, address_left, '0.50000000')
            except NetworkError as error:
                report['observations']['same_tip_prepare_error'] = error.code
                assert error.code == 'network_identity'
            else:
                raise AssertionError('Identical-tip partition was incorrectly accepted by prepare')
            response = left.app.handle({'id': 999999, 'command': 'confirm_send', 'params': {'preview_id': preview['preview_id']}})
            assert response['ok'] is False
            report['observations']['same_tip_confirm_error'] = response['error']['code']
            assert network.payment_status(left.record(funding['txid']))['status'] == 'pending'
            unavailable = left.app.state()
            assert unavailable['network_healthy'] is False and unavailable['balance'] is None
            assert all(record['status'] != 'confirmed' for record in left.app.history.records())
        assert blocked_calls == {'sign': 0, 'sendrawtransaction': 0}
        assert all(controller.rpc(index, 'getblockcount') == start_height for index in range(4))
        report['checks']['identical_tip_partition_refuses_prepare_sign_broadcast_and_confirmation'] = True
        controller.reconnect()
        assert left.request('refresh')['balance'] == '1.00000000'
        assert right.request('refresh')['balance'] == '1.00000000'

        preview_left, signed_left = left.prepare(address_left)
        preview_right, signed_right = right.prepare(address_right)
        assert signed_left.txid_hex != signed_right.txid_hex
        assert [(item.prevout.hash, item.prevout.n) for item in signed_left.vin] == [(item.prevout.hash, item.prevout.n) for item in signed_right.vin]
        assert all(controller.rpc(index, 'testmempoolaccept', [signed.serialize_with_witness().hex()])[0]['allowed']
                   for signed in (signed_left, signed_right) for index in range(4))
        candidate = controller.rpc(0, 'generateblock', left.address,
                                   [signed_left.serialize_with_witness().hex()], False)['hex']
        invalid_block = from_hex(CBlock(), candidate)
        invalid_block.vtx.append(CTransaction(signed_right))
        add_witness_commitment(invalid_block)
        invalid_block.hashMerkleRoot = invalid_block.calc_merkle_root()
        rejected_blocks = []
        for index in range(4):
            # Distinct solved headers keep peers' invalid-header announcements
            # from substituting a cached rejection for this node's validation.
            invalid_block.nNonce += 1
            invalid_block.solve()
            reason = controller.rpc(index, 'submitblock', invalid_block.serialize().hex())
            rejected_blocks.append(reason)
            assert reason == 'bad-txns-inputs-missingorspent'
        assert all(controller.rpc(index, 'getbestblockhash') == common_tip for index in range(4))
        assert all(controller.rpc(index, 'gettxout', f'{signed_left.vin[0].prevout.hash:064x}',
                                  signed_left.vin[0].prevout.n, True) for index in range(4))
        report['observations']['direct_block_rejections'] = rejected_blocks
        report['checks']['all_four_nodes_reject_validly_signed_double_spend_block_without_advancing_tip'] = True
        left.authorize_fixture_branch(preview_left, signed_left, start_height)
        right.authorize_fixture_branch(preview_right, signed_right, start_height)
        controller.partition()
        raws = [signed_left.serialize_with_witness().hex(), signed_right.serialize_with_witness().hex()]
        txids = [signed_left.txid_hex, signed_right.txid_hex]
        for group, raw, txid in zip(GROUPS, raws, txids):
            leader = min(group)
            assert controller.rpc(leader, 'sendrawtransaction', raw) == txid
            deadline = time.monotonic() + 20
            while not all(txid in controller.rpc(index, 'getrawmempool') for index in group):
                assert time.monotonic() < deadline
                time.sleep(.1)
        conflicts = []
        for group, conflicting_raw in zip(GROUPS, reversed(raws)):
            for index in sorted(group):
                rejection = controller.rpc(index, 'testmempoolaccept', [conflicting_raw])[0]
                assert rejection.get('allowed') is False
                conflicts.append({'node': index, 'reject_reason': rejection.get('reject-reason')})
            try:
                controller.rpc(min(group), 'sendrawtransaction', conflicting_raw)
            except RpcError as error:
                assert error.code == -26
            else:
                raise AssertionError('Conflicting mempool spend accepted')
        for group, original, rival in ((GROUPS[0], txids[0], txids[1]), (GROUPS[1], txids[1], txids[0])):
            for index in group:
                pool = controller.rpc(index, 'getrawmempool')
                assert original in pool and rival not in pool
        report['observations']['mempool_conflicts'] = conflicts
        report['checks']['same_input_conflicts_rejected_on_each_partition_without_replacing_original'] = True

        left_tip = controller.rpc(0, 'generateblock', left.address, [raws[0]])['hash']
        controller.group_synced({0, 1}, left_tip)
        left_header_raw = controller.rpc(0, 'getblockheader', left_tip, False)
        winning_block = controller.rpc(2, 'generateblock', left.address, [raws[1]])['hash']
        controller.group_synced({2, 3}, winning_block)
        right_tip = controller.rpc(2, 'generateblock', left.address, [])['hash']
        controller.group_synced({2, 3}, right_tip)
        controller.assert_partition()
        work_left = int(controller.rpc(0, 'getblockchaininfo')['chainwork'], 16)
        work_right = int(controller.rpc(2, 'getblockchaininfo')['chainwork'], 16)
        assert work_right > work_left
        assert all(controller.rpc(i, 'gettxout', txids[0], 0, True) for i in (0, 1))
        assert all(controller.rpc(i, 'gettxout', txids[1], 0, True) for i in (2, 3))
        assert network.payment_status(left.record(txids[0]))['status'] == 'pending'
        assert network.payment_status(right.record(txids[1]))['status'] == 'pending'
        report['observations']['branch_work'] = {'left': f'{work_left:x}', 'right': f'{work_right:x}'}
        report['checks']['two_valid_conflicting_branches_have_strictly_different_work_no_four_node_receipt'] = True

        controller.reconnect()
        assert controller.wait_synced(right_tip) == right_tip
        utxo_hash = common_utxos(controller, right_tip)
        for index in range(4):
            assert controller.rpc(index, 'getblockhash', start_height + 1) == winning_block
            assert controller.rpc(index, 'gettxout', txids[1], 0, True)
            assert not controller.rpc(index, 'gettxout', txids[0], 0, True)
            assert txids[0] not in controller.rpc(index, 'getrawmempool')
            assert not controller.rpc(index, 'gettxout', f'{signed_left.vin[0].prevout.hash:064x}', signed_left.vin[0].prevout.n, True)
        report['observations']['converged_utxo_hash'] = utxo_hash
        report['checks']['reconnected_nodes_choose_higher_work_and_identical_utxo_set'] = True
        state_left = left.request('refresh')
        state_right = right.request('refresh')
        source_input = {'txid': f'{signed_left.vin[0].prevout.hash:064x}', 'vout': signed_left.vin[0].prevout.n}
        expected_conflict = {'txid': txids[1], 'block': winning_block,
                             'height': start_height + 1, 'input': source_input}
        losing_record = left.record(txids[0])
        assert losing_record['status'] == 'conflicted' and losing_record['confirmed_nodes'] == 4
        assert losing_record['conflict'] == expected_conflict
        assert losing_record['transaction'] == signed_left.serialize_without_witness().hex()
        assert not state_left['payment_blocked']
        assert not state_right['payment_blocked'] and right.record(txids[1])['status'] == 'confirmed'
        assert state_left['balance'] == state_right['balance'] == '0.49900000'
        report['observations']['verified_conflict'] = expected_conflict
        report['checks']['four_node_conflict_proof_releases_loser_guard_and_confirms_winner'] = True

        # Losing records may retain a block hint from a prior confirmation.
        # A node no longer knowing that orphan header must not hide an otherwise
        # fully verifiable active-chain conflict. Other RPC failures stay pending.
        original_rpc = controller.rpc
        missing_headers = {'count': 0}
        def missing_orphan_header(index, method, *args, **kwargs):
            if method == 'getblockheader' and args[0] == left_tip:
                missing_headers['count'] += 1
                raise RpcError('Fixture orphan header unavailable', -5)
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(controller, 'rpc', side_effect=missing_orphan_header):
            still_proven = network.payment_status({**losing_record, 'block': left_tip})
        assert missing_headers['count'] > 0
        assert still_proven['status'] == 'conflicted' and still_proven['confirmed_nodes'] == 4
        assert still_proven['conflict'] == expected_conflict
        report['checks']['missing_orphan_header_still_allows_exact_active_conflict_proof'] = True

        legacy = legacy_pending_history(directory, left, txids[0])
        histories.append(legacy)
        legacy_record = legacy.records()[0]
        assert 'transaction' not in legacy_record
        legacy_status = network.payment_status(legacy_record)
        assert legacy_status['status'] == 'pending'
        legacy.update(legacy_record['operation_id'], legacy_status)
        assert legacy.blocked and legacy.records()[0]['status'] == 'pending'
        report['checks']['legacy_journal_without_transaction_remains_pending_after_migration'] = True

        height = controller.rpc(0, 'getblockcount')
        original_rpc = controller.rpc
        with patch.object(controller, 'rpc', side_effect=no_broadcast), \
                patch.object(right.app.session, 'sign', side_effect=no_sign), \
                patch.object(left.app.session, 'sign', side_effect=no_sign):
            assert right.request('confirm_send', {'preview_id': preview_right['preview_id']})['payment']['txid'] == txids[1]
            left.request('confirm_send', {'preview_id': preview_left['preview_id']}, error='payment_conflicted')
            left.request('recover_payments')
        assert blocked_calls == {'sign': 0, 'sendrawtransaction': 0}
        assert controller.rpc(0, 'getblockcount') == height
        report['checks']['original_conflicted_operation_cannot_be_replayed_signed_or_broadcast'] = True

        # Corrupt one node's public serialized conflict proof while every real
        # node remains healthy. A valid receipt cannot be inferred from the
        # other three nodes or from the previously saved receipt.
        altered = {'count': 0}
        original_rpc = controller.rpc
        def wrong_proof(index, method, *args, **kwargs):
            assert method not in {'sendrawtransaction', 'generateblock'}
            value = original_rpc(index, method, *args, **kwargs)
            if index == 3 and method == 'getblock' and args[0] == winning_block and isinstance(value, dict):
                for transaction in value.get('tx', []):
                    if isinstance(transaction, dict) and transaction.get('txid') == txids[1] and 'hex' in transaction:
                        transaction['hex'] += '00'
                        altered['count'] += 1
            return value
        with patch.object(controller, 'rpc', side_effect=wrong_proof):
            left.request('refresh')
        assert altered['count'] > 0
        assert left.record(txids[0])['status'] == 'pending' and left.app.state()['payment_blocked']
        assert not left.request('refresh')['payment_blocked']
        assert left.record(txids[0])['status'] == 'conflicted'
        report['checks']['wrong_proof_from_one_node_revokes_conflict_until_reverified'] = True

        stale_preview = left.request('prepare_send', {'recipient': address_left, 'amount': '0.10000000'})
        assert left.record(txids[0])['status'] == 'conflicted'
        # Invalidating only the winner would activate the other signed fork.
        # Invalidate both fixture fork blocks so the original chain input really
        # returns. The winner can remain in the mempool; that is not chain proof.
        report['observations']['losing_header_distribution'] = share_known_losing_header(
            controller, left_tip, left_header_raw, right_tip, work_left, work_right,
            expected_parent=common_tip, expected_height=start_height + 1)
        report['checks']['known_losing_fixture_header_shared_without_changing_winning_chain'] = True
        for index in range(4):
            controller.rpc(index, 'invalidateblock', left_tip)
            controller.rpc(index, 'invalidateblock', winning_block)
        controller.wait_synced(common_tip)
        assert all(controller.rpc(index, 'gettxout', source_input['txid'], source_input['vout'], False)
                   for index in range(4))
        assert left.record(txids[0])['status'] == 'conflicted'  # Deliberately stale cached receipt.
        original_rpc = controller.rpc
        with patch.object(controller, 'rpc', side_effect=no_broadcast), patch.object(left.app.session, 'sign', side_effect=no_sign):
            value = left.app.handle({'id': 999998, 'command': 'confirm_send',
                                     'params': {'preview_id': stale_preview['preview_id']}})
            assert not value['ok'] and value['error']['code'] in {'payment_pending', 'preview_invalid'}
        assert blocked_calls == {'sign': 0, 'sendrawtransaction': 0}
        assert left.record(txids[0])['status'] == 'pending' and left.app.state()['payment_blocked']
        report['checks']['reorg_restores_original_input_and_stale_preview_is_blocked_before_signing'] = True
        for index in range(4):
            controller.rpc(index, 'reconsiderblock', winning_block)
        controller.wait_synced(right_tip)
        controller.reconnect()
        assert not left.request('refresh')['payment_blocked']
        assert left.record(txids[0])['status'] == 'conflicted'
        assert left.record(txids[0])['conflict'] == expected_conflict
        report['checks']['restored_winning_chain_reestablishes_same_conflict_proof'] = True

        fresh_preview = left.request('prepare_send', {'recipient': address_left, 'amount': '0.10000000'})
        original_rpc = controller.rpc
        fresh_calls = {'sign': 0, 'broadcast': 0}
        original_sign = left.app.session.sign
        def sign_new(*args, **kwargs):
            fresh_calls['sign'] += 1
            return original_sign(*args, **kwargs)
        def broadcast_new(index, method, *args, **kwargs):
            if method == 'sendrawtransaction':
                fresh_calls['broadcast'] += 1
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(controller, 'rpc', side_effect=broadcast_new), patch.object(left.app.session, 'sign', side_effect=sign_new):
            fresh_payment = left.request('confirm_send', {'preview_id': fresh_preview['preview_id']})['payment']
        assert fresh_calls == {'sign': 1, 'broadcast': 1}
        assert fresh_payment['txid'] not in txids and fresh_payment['confirmed_nodes'] == 4
        assert left.request('refresh')['balance'] == '0.39800000'
        assert right.request('refresh')['balance'] == '0.39800000'
        report['checks']['separately_reviewed_payment_spends_remaining_change_exactly_once'] = True

        controller.stop_one(3)
        original_rpc = controller.rpc
        with patch.object(controller, 'rpc', side_effect=no_broadcast), patch.object(left.app.session, 'sign', side_effect=no_sign):
            try:
                network.prepare(left.app.keys, address_right, '0.10000000')
            except NetworkError as error:
                assert error.code == 'network_identity'
            else:
                raise AssertionError('Offline fourth node incorrectly authorized payment')
            assert network.payment_status(left.record(txids[0]))['status'] == 'pending'
            offline = left.app.handle({'id': 999997, 'command': 'refresh', 'params': {}})
            assert not offline['ok']
        assert left.record(txids[0])['status'] == 'pending' and left.app.state()['payment_blocked']
        assert blocked_calls == {'sign': 0, 'sendrawtransaction': 0}
        offline_tip = controller.rpc(0, 'generateblock', left.address, [])['hash']
        controller.group_synced({0, 1, 2}, offline_tip)
        controller.start_one(3)
        controller.reconnect()
        assert controller.wait_synced(offline_tip) == offline_tip
        common_utxos(controller, offline_tip)
        assert left.request('refresh')['balance'] == '0.39800000'
        assert left.record(txids[0])['status'] == 'conflicted' and not left.app.state()['payment_blocked']
        assert right.request('refresh')['balance'] == '0.39800000'
        assert right.record(txids[1])['status'] == 'confirmed'
        report['checks']['offline_node_revokes_conflict_then_resynchronization_reproves_it'] = True

        height = controller.rpc(0, 'getblockcount')
        original_rpc = controller.rpc
        with patch.object(controller, 'rpc', side_effect=no_broadcast), \
                patch.object(right.app.session, 'sign', side_effect=no_sign), \
                patch.object(left.app.session, 'sign', side_effect=no_sign):
            assert right.request('confirm_send', {'preview_id': preview_right['preview_id']})['payment']['txid'] == txids[1]
            assert left.request('confirm_send', {'preview_id': fresh_preview['preview_id']})['payment']['txid'] == fresh_payment['txid']
            left.request('confirm_send', {'preview_id': preview_left['preview_id']}, error='payment_conflicted')
        assert blocked_calls == {'sign': 0, 'sendrawtransaction': 0}
        assert controller.rpc(0, 'getblockcount') == height
        report['checks']['winner_and_fresh_payment_replays_do_not_duplicate_transactions_or_fees'] = True

        for wallet in wallets:
            wallet.app.close()
        probe_reopen(left, data_name, balance='0.39800000',
                     statuses={txids[0]: 'conflicted', fresh_payment['txid']: 'confirmed'},
                     replays=[{'operation_id': preview_left['preview_id'], 'error': 'payment_conflicted'},
                              {'operation_id': fresh_preview['preview_id'], 'txid': fresh_payment['txid']}])
        probe_reopen(right, data_name, balance='0.39800000', statuses={txids[1]: 'confirmed'},
                     replays=[{'operation_id': preview_right['preview_id'], 'txid': txids[1]}])
        report['worker_processes'] = 2
        report['checks']['fresh_bridge_processes_and_node_restarts_reverify_conflict_and_exact_replay'] = True
        report['transactions'] = {'funding': funding['txid'], 'loser': txids[0], 'winner': txids[1],
                                  'fresh_payment': fresh_payment['txid']}
        report['passed'] = True
    except BaseException as error:
        report.update(failure_location(error))
        report['last_operations'] = [{'command': wallet.last_command, 'error_code': wallet.last_error} for wallet in wallets]
        raise
    finally:
        cleanup = True
        for history in histories:
            try:
                history.close()
            except BaseException:
                cleanup = False
        for wallet in wallets:
            try:
                wallet.app.close()
            except BaseException:
                cleanup = False
        for network in networks:
            try:
                network.stop()
            except BaseException:
                cleanup = False
        report['cleanup'] = 'owned-nodes-stopped' if cleanup else 'needs-attention'
        report['ports_free'] = ports_free()
        report['source_sha256_at_end'] = hashes()
        report['source_unchanged'] = report['source_sha256_at_start'] == report['source_sha256_at_end']
        report['binary_sha256_at_end'] = binary_hashes()
        report['binaries_unchanged'] = report['binary_sha256_at_start'] == report['binary_sha256_at_end']
        report['passed'] = (report['passed'] and cleanup and all(report['ports_free'].values())
                            and report['source_unchanged'] and report['binaries_unchanged'])
        report['completed_at'] = datetime.now(timezone.utc).isoformat()
        report['controller_failures'] = [network.controller.start_failure for network in networks
                                         if network.controller.start_failure is not None]
        if not report['passed']:
            # Preserve the safe failure location even if writing evidence fails.
            print(json.dumps(failure_summary(report), indent=2), flush=True)
        evidence = protocol.ROOT / '.local/evidence'
        secure_directory(evidence)
        for destination in (directory / 'result.json', evidence / 'network-resilience-latest.json'):
            destination.write_text(json.dumps(report, indent=2) + '\n')
            destination.chmod(0o600)
    return report


if __name__ == '__main__':
    if sys.argv[1:] == ['--reopen-worker']:
        reopen_worker()
        raise SystemExit(0)
    try:
        result = run()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['passed'] else 1)
    except Exception:
        print('QLU network-resilience drill failed; see its public evidence report.', file=sys.stderr)
        raise SystemExit(1)

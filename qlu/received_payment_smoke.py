#!/usr/bin/env python3
"""Real four-node, two-wallet incoming-history drill; fresh valueless fixtures only."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import socket
import sys
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
import protocol
from payment_history_smoke import wait_pooled
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork


class Wallet:
    def __init__(self, network, directory, label):
        self.directory = directory / label
        secure_directory(self.directory)
        self.password = secrets.token_urlsafe(32)
        self.app_dir = protocol.ROOT / '.local' / ('wallet-app-received-' + uuid.uuid4().hex)
        self.counter = 0
        self.last_command = self.last_error = None
        self.app = WalletApp(root=protocol.ROOT, network=network, app_dir=self.app_dir)
        self.path = self.request('create', {'passphrase': self.password, 'confirmation': self.password})['wallet_path']
        backup = self.directory / 'backup.json'
        code = self.request('backup_create', {'backup_path': str(backup)})['code']
        state = self.request('backup_verify', {'backup_path': str(backup), 'code': code})
        self.address = state['address']

    def request(self, command, params=None, *, error=None):
        self.last_command = command
        self.counter += 1
        value = self.app.handle({'id': self.counter, 'command': command, 'params': params or {}})
        self.last_error = value.get('error', {}).get('code')
        if error is not None:
            assert value.get('ok') is False and self.last_error == error, command
            return value['error']
        assert value.get('ok') is True, command
        return value['result']

    def reopen(self, network):
        self.app = WalletApp(root=protocol.ROOT, network=network, app_dir=self.app_dir)
        self.request('open', {'path': self.path})
        state = self.request('unlock', {'passphrase': self.password})
        assert state['backup_verified'] and state['address'] == self.address

    def send(self, recipient, amount):
        preview = self.request('prepare_send', {'recipient': recipient, 'amount': amount})
        assert not preview['is_self_transfer'] and preview['wallet_debit'] != preview['fee']
        token = preview['preview_id']
        return token, self.request('confirm_send', {'preview_id': token})['payment']

    def incoming(self, txid):
        return self.request('verify_received', {'txid': txid})['received']

    def record(self, txid):
        return next(row for row in self.app.history.records() if row.get('txid') == txid)


def ports_free():
    result = {}
    for port in (*range(28440, 28444), *range(28540, 28544)):
        with socket.socket() as client:
            result[str(port)] = client.connect_ex(('127.0.0.1', port)) != 0
    return result


def run():
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / '.local/received-payment-drills'
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    report = {'attempt': identifier, 'started_at': datetime.now(timezone.utc).isoformat(),
              'passed': False, 'checks': {}, 'transactions': {},
              'scope': 'Fresh two-wallet fixtures, actual four private nodes on one Mac; no user wallet or native UI claim.'}
    wallets = []
    networks = []
    data_name = 'wallet-app-received-net-' + identifier

    def new_network():
        value = WalletAppNetwork(root=protocol.ROOT, data_name=data_name, process_label='QLUWalletAppReceived')
        networks.append(value)
        return value

    try:
        assert all(ports_free().values()), 'Private laboratory ports must be free before this drill'
        network = new_network()
        sender = Wallet(network, directory, 'sender')
        wallets.append(sender)
        receiver = Wallet(network, directory, 'receiver')
        wallets.append(receiver)
        assert sender.address != receiver.address
        sender.request('network_start')
        funding_id = uuid.uuid4().hex
        funding = sender.request('faucet', {'operation_id': funding_id})['payment']
        token, payment = sender.send(receiver.address, '0.10000000')
        incoming = receiver.incoming(payment['txid'])
        assert incoming['kind'] == 'receive' and incoming['amount'] == '0.10000000' and 'fee' not in incoming
        assert sender.request('refresh')['balance'] == '0.89900000'
        assert receiver.request('refresh')['balance'] == '0.10000000'
        report['checks']['distinct_wallet_payment_and_chain_verified_incoming_balances'] = True

        height = network.controller.rpc(0, 'getblockcount')
        original_rpc = network.controller.rpc
        def read_only(index, method, *args, **kwargs):
            assert method not in {'sendrawtransaction', 'generateblock', 'generatetoaddress'}, 'read-only receive/replay'
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(network.controller, 'rpc', side_effect=read_only), \
                patch.object(sender.app.session, 'sign', side_effect=AssertionError('must not sign')), \
                patch.object(receiver.app.session, 'sign', side_effect=AssertionError('must not sign')):
            assert receiver.incoming(payment['txid'])['operation_id'] == incoming['operation_id']
            assert sender.request('confirm_send', {'preview_id': token})['payment']['txid'] == payment['txid']
        assert receiver.request('refresh')['history_count'] == 1
        assert network.controller.rpc(0, 'getblockcount') == height
        report['checks']['incoming_and_sender_token_replay_create_no_transaction_or_duplicate'] = True

        for wallet in wallets:
            wallet.app.close()
        network = new_network()
        for wallet in wallets:
            wallet.reopen(network)
        sender.request('network_start')
        assert sender.request('refresh')['balance'] == '0.89900000'
        assert receiver.request('refresh')['balance'] == '0.10000000'
        assert receiver.record(payment['txid'])['status'] == 'confirmed'
        assert receiver.request('refresh')['history_count'] == 1
        report['checks']['both_wallet_and_node_restarts_preserve_backup_gate_history_and_balances'] = True

        _, returned = receiver.send(sender.address, '0.09900000')
        assert receiver.request('refresh')['balance'] == '0.00000000'
        assert sender.request('refresh')['balance'] == '0.99800000'
        for index in range(4):
            assert not network.controller.rpc(index, 'gettxout', payment['txid'], 0, True)
        assert receiver.incoming(payment['txid'])['status'] == 'confirmed'
        assert sender.incoming(returned['txid'])['amount'] == '0.09900000'
        report['checks']['spent_incoming_output_remains_verifiable_from_block_and_undo'] = True

        receiver.request('verify_received', {'txid': funding['txid']}, error='incoming_not_received')
        sender.request('verify_received', {'txid': payment['txid']}, error='incoming_not_received')
        receiver.request('verify_received', {'txid': '00' * 32}, error='incoming_not_found')
        receiver.request('verify_received', {'txid': 'not-a-transaction'}, error='invalid_transaction')
        report['checks']['foreign_self_change_unknown_and_malformed_transactions_are_refused'] = True

        receiver.request('faucet', {'operation_id': uuid.uuid4().hex})
        _, reorg_payment = sender.send(receiver.address, '0.10000000')
        first_receipt = receiver.incoming(reorg_payment['txid'])
        for index in range(4):
            network.controller.rpc(index, 'invalidateblock', reorg_payment['block'])
        network.controller.wait_synced()
        wait_pooled(network, reorg_payment['txid'])
        state = receiver.request('refresh')
        assert receiver.record(reorg_payment['txid'])['status'] == 'pending'
        assert not state['payment_blocked'] and state['balance'] == '1.00000000'
        height = network.controller.rpc(0, 'getblockcount')
        original_rpc = network.controller.rpc
        with patch.object(network.controller, 'rpc', side_effect=read_only), \
                patch.object(receiver.app.session, 'sign', side_effect=AssertionError('must not sign')):
            state = receiver.request('recover_payments')
        assert receiver.record(reorg_payment['txid'])['status'] == 'pending' and not state['payment_blocked']
        assert network.controller.rpc(0, 'getblockcount') == height
        receiver.send(sender.address, '0.05000000')
        assert receiver.request('refresh')['balance'] == '0.94900000'
        report['checks']['incoming_reorg_downgrades_read_only_without_blocking_other_outgoing'] = True

        original_rpc = network.controller.rpc
        generated = []
        def existing_only(index, method, *args, **kwargs):
            assert method != 'sendrawtransaction', 'must not rebroadcast'
            if method == 'generateblock':
                generated.append(args[1])
                assert args[1] == [reorg_payment['txid']]
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(network.controller, 'rpc', side_effect=existing_only), \
                patch.object(sender.app.session, 'sign', side_effect=AssertionError('must not sign')):
            sender.request('recover_payments')
        assert generated == [[reorg_payment['txid']]]
        assert receiver.request('refresh')['balance'] == '1.04900000'
        final_receipt = receiver.record(reorg_payment['txid'])
        assert final_receipt['status'] == 'confirmed' and final_receipt['block'] != reorg_payment['block']
        assert final_receipt['amount'] == first_receipt['amount'] and final_receipt['start_height'] == first_receipt['start_height']
        report['checks']['same_existing_transaction_reconfirms_incoming_with_original_amount_and_origin'] = True
        report['transactions'] = {'sent': payment['txid'], 'returned': returned['txid'], 'reorg_reconfirmed': reorg_payment['txid']}
        report['passed'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__
        report['error_location'] = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                                    for frame in traceback.extract_tb(error.__traceback__)]
        report['last_operations'] = [{'command': wallet.last_command, 'error_code': wallet.last_error} for wallet in wallets]
        raise
    finally:
        cleanup = True
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
        report['passed'] = report['passed'] and cleanup and all(report['ports_free'].values())
        report['completed_at'] = datetime.now(timezone.utc).isoformat()
        report['source_sha256'] = {name: hashlib.sha256((protocol.ROOT / 'qlu' / name).read_bytes()).hexdigest()
                                   for name in ('wallet_app_network.py', 'wallet_app.py', 'payment_history.py', 'received_payment_smoke.py')}
        evidence = protocol.ROOT / '.local/evidence'
        secure_directory(evidence)
        for destination in (directory / 'result.json', evidence / 'received-payment-latest.json'):
            destination.write_text(json.dumps(report, indent=2) + '\n')
            destination.chmod(0o600)
    return report


if __name__ == '__main__':
    try:
        result = run()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['passed'] else 1)
    except Exception:
        print('QLU received-payment drill failed; see its public evidence report.', file=sys.stderr)
        raise SystemExit(1)

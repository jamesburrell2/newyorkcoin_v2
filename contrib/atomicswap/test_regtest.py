#!/usr/bin/env python3
# Copyright (c) 2026 The NewYorkCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
End-to-end regtest test for nyc_atomicswap.py.

Starts two independent nycd regtest nodes that stand in for two separate
chains ("NYC" and "OTHER"), then runs:
  1. a complete swap (initiate, audit, participate, audit, redeem,
     extractsecret, redeem),
  2. consensus-level negative checks (wrong secret, early refund, wrong key),
  3. a refund after the CSV timelock expires.

Usage:  python3 test_regtest.py /path/to/src/nycd
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from decimal import Decimal

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "nyc_atomicswap.py")
sys.path.insert(0, HERE)
import nyc_atomicswap as swap  # noqa: E402


class Node:
    def __init__(self, nycd, name, rpcport, p2pport, root):
        self.name, self.rpcport = name, rpcport
        self.datadir = os.path.join(root, name)
        os.makedirs(self.datadir)
        self.proc = subprocess.Popen([
            nycd, "-regtest", f"-datadir={self.datadir}", f"-rpcport={rpcport}",
            f"-port={p2pport}", "-listen=0", "-connect=0", "-rpcuser=u", "-rpcpassword=p",
            "-fallbackfee=0.0001", "-txindex=0", "-printtoconsole=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"http://127.0.0.1:{rpcport}"
        for _ in range(120):
            try:
                self.rpc()("getblockcount")
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError(f"{name} did not start")

    def rpc(self, wallet=None):
        return swap.RPC(self.url, "u", "p", wallet=wallet)

    def mine(self, n, wallet="miner"):
        addr = self.rpc(wallet)("getnewaddress")
        self.rpc()("generatetoaddress", n, addr)

    def stop(self):
        try:
            self.rpc()("stop")
            self.proc.wait(timeout=60)
        except Exception:
            self.proc.kill()


def tool(node, wallet, state, *args, expect_fail=False):
    cmd = [sys.executable, "-I", TOOL, args[0], "--state", state, "--rpcurl", node.url,
           "--rpcuser", "u", "--rpcpassword", "p", "--rpcwallet", wallet, *args[1:]]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if expect_fail:
        assert res.returncode != 0, f"expected failure: {' '.join(args)}\n{res.stdout}"
        return res.stderr + res.stdout
    assert res.returncode == 0, f"{' '.join(args)} failed:\n{res.stderr}\n{res.stdout}"
    return json.loads(res.stdout)


def keygen(state):
    res = subprocess.run([sys.executable, "-I", TOOL, "keygen", "--state", state],
                         capture_output=True, text=True, check=True)
    return json.loads(res.stdout)["pubkey"]


def balance(node, wallet):
    return Decimal(str(node.rpc(wallet)("getbalance")))


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print(f"  PASS  {msg}")


def main():
    nycd = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "src", "nycd")
    root = tempfile.mkdtemp(prefix="nycswap-")
    nyc = other = None
    try:
        nyc = Node(nycd, "nyc", 28601, 28600, root)
        other = Node(nycd, "other", 28611, 28610, root)
        for n in (nyc, other):
            for w in ("miner", "alice", "bob"):
                n.rpc()("createwallet", w)
            n.mine(500)  # past CSVHeight=432 on regtest, plus coinbase maturity
        info = nyc.rpc()("getblockchaininfo")
        check(info["softforks"]["csv"]["active"], "CSV is active on regtest after block 432")

        nyc.rpc("miner")("sendtoaddress", nyc.rpc("alice")("getnewaddress"), 100)
        other.rpc("miner")("sendtoaddress", other.rpc("bob")("getnewaddress"), 100)
        nyc.mine(1); other.mine(1)

        a_state, b_state = os.path.join(root, "alice.json"), os.path.join(root, "bob.json")
        a_pub, b_pub = keygen(a_state), keygen(b_state)

        print("\n[1] Full swap: Alice trades 40 NYC for 10 OTHER")
        init = tool(nyc, "alice", a_state, "initiate", "--their-pubkey", b_pub, "--amount", "40",
                    "--locktime-blocks", "60", "--leg", "nyc")
        nyc.mine(1)
        aud = tool(nyc, "bob", b_state, "audit", "--contract", init["contract"],
                   "--contract-tx", init["contract_tx"], "--expect-amount", "40")
        check(aud["pays_to_me"] and aud["amount"] == "40.00000000" and aud["confirmations"] == 1,
              "Bob's audit of Alice's NYC contract is clean")

        part = tool(other, "bob", b_state, "participate", "--their-pubkey", a_pub, "--amount", "10",
                    "--secret-hash", aud["secret_hash"], "--locktime-blocks", "30", "--leg", "other")
        other.mine(1)
        aud2 = tool(other, "alice", a_state, "audit", "--contract", part["contract"],
                    "--contract-tx", part["contract_tx"], "--expect-amount", "10",
                    "--expect-secret-hash", init["secret_hash"])
        check(aud2["pays_to_me"], "Alice's audit of Bob's OTHER contract is clean")

        # Bob must not be able to refund before the timelock, nor redeem without the secret.
        out = tool(other, "bob", b_state, "refund", "--leg", "other", expect_fail=True)
        check("timelock not expired" in out, "early refund is refused by the tool")

        a_before = balance(other, "alice")
        red = tool(other, "alice", a_state, "redeem", "--contract", part["contract"],
                   "--contract-tx", part["contract_tx"])
        other.mine(1)
        check(balance(other, "alice") - a_before == Decimal(red["amount"]),
              f"Alice redeemed {red['amount']} OTHER (fee {red['fee']})")

        sec = tool(other, "bob", b_state, "extractsecret", "--leg", "other")
        check(swap.sha256(bytes.fromhex(sec["secret"])).hex() == init["secret_hash"],
              "Bob extracted the correct secret from Alice's redemption")

        b_before = balance(nyc, "bob")
        red2 = tool(nyc, "bob", b_state, "redeem", "--contract", init["contract"],
                    "--contract-tx", init["contract_tx"])
        nyc.mine(1)
        check(balance(nyc, "bob") - b_before == Decimal(red2["amount"]),
              f"Bob redeemed {red2['amount']} NYC; swap complete")

        print("\n[2] Consensus-level negative checks")
        a2, b2 = os.path.join(root, "alice2.json"), os.path.join(root, "bob2.json")
        a2_pub, b2_pub = keygen(a2), keygen(b2)
        init2 = tool(nyc, "alice", a2, "initiate", "--their-pubkey", b2_pub, "--amount", "5",
                     "--locktime-blocks", "10", "--leg", "nyc")
        nyc.mine(1)
        contract = bytes.fromhex(init2["contract"])
        terms = swap.parse_contract(contract)
        ftx = swap.parse_tx(bytes.fromhex(init2["contract_tx"]))
        vout = init2["contract_vout"]
        value = ftx["vout"][vout]["value"]
        spk = bytes.fromhex(nyc.rpc("alice")("validateaddress",
                                             nyc.rpc("alice")("getnewaddress"))["scriptPubKey"])

        def spend(priv, seq, scriptsig_fn, version=2):
            tx = {"version": version, "locktime": 0,
                  "vin": [{"txid": init2["contract_txid"], "vout": vout, "scriptSig": b"", "sequence": seq}],
                  "vout": [{"value": value - 10000, "scriptPubKey": spk}]}
            sig = swap.ecdsa_sign(priv, swap.legacy_sighash(tx, 0, contract)) + b"\x01"
            tx["vin"][0]["scriptSig"] = scriptsig_fn(sig)
            return nyc.rpc()("testmempoolaccept", [swap.serialize_tx(tx).hex()])[0]

        a2_priv = bytes.fromhex(json.load(open(a2))["privkey"])
        b2_priv = bytes.fromhex(json.load(open(b2))["privkey"])
        r = spend(b2_priv, 0xFFFFFFFF, lambda s: swap.redeem_script_sig(s, b"\x00" * 32, contract))
        check(not r["allowed"], f"redeem with a wrong secret is rejected ({r.get('reject-reason')})")
        r = spend(b2_priv, 0xFFFFFFFF, lambda s: swap.redeem_script_sig(s, b"\x00" * 31, contract))
        check(not r["allowed"], "31-byte secret is rejected by the OP_SIZE check")
        r = spend(a2_priv, terms["lock_blocks"], lambda s: swap.refund_script_sig(s, contract))
        check(not r["allowed"] and "BIP68" in r.get("reject-reason", ""),
              f"refund before CSV expiry is rejected ({r.get('reject-reason')})")
        r = spend(b2_priv, terms["lock_blocks"], lambda s: swap.refund_script_sig(s, contract))
        check(not r["allowed"], "refund signed by the wrong key is rejected")
        r = spend(a2_priv, 0xFFFFFFFF, lambda s: swap.refund_script_sig(s, contract))
        check(not r["allowed"], "refund with nSequence lock disabled is rejected")

        print("\n[3] Refund after timelock")
        nyc.mine(terms["lock_blocks"] - 2)  # 1 + 8 = 9 confirmations, still 1 short
        out = tool(nyc, "alice", a2, "refund", "--leg", "nyc", expect_fail=True)
        check("timelock not expired" in out, "refund one block early is refused")
        nyc.mine(1)
        a_before = balance(nyc, "alice")
        ref = tool(nyc, "alice", a2, "refund", "--leg", "nyc")
        nyc.mine(1)
        check(balance(nyc, "alice") - a_before == Decimal(ref["amount"]),
              f"Alice refunded {ref['amount']} NYC after exactly {terms['lock_blocks']} confirmations")
        out = tool(nyc, "bob", b2, "extractsecret", "--contract", init2["contract"],
                   "--contract-tx", init2["contract_tx"],
                   "--from-height", str(nyc.rpc()("getblockcount") - 15), expect_fail=True)
        check("REFUNDED" in out, "extractsecret reports a refund instead of a secret")

        print("\nAll atomic swap tests passed.")
    finally:
        for n in (nyc, other):
            if n:
                n.stop()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()

# NYC Atomic Swaps

Trustless peer-to-peer swaps between NewYorkCoin and Bitcoin, Litecoin, or any
other Bitcoin-family chain that supports P2SH and `OP_CHECKSEQUENCEVERIFY`
(BIP68/112). No exchange, escrow agent, or custodian is involved: either both
sides get paid, or both sides get their coins back.

`nyc_atomicswap.py` is a single Python 3.7+ file with no dependencies. It talks
to your own full nodes over JSON-RPC.

## Why this uses CSV instead of CLTV

Most existing atomic swap tools (e.g. the Decred `atomicswap` suite) put the
refund behind `OP_CHECKLOCKTIMEVERIFY`. **That is unsafe on NYC mainnet.**
BIP65 is not enforced (`BIP65Height = INT_MAX` in `chainparams.cpp`), so
`OP_CLTV` executes as `OP_NOP2` and a CLTV refund branch can be spent by anyone,
immediately.

BIP68/112 (CSV) **is** enforced from block **13,000,000**, so every contract
here uses a relative timelock measured in blocks since the contract confirmed.
The tool checks that CSV is active on each chain and refuses to lock funds if
it is not.

## The contract

```
OP_IF
    OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <secret_hash> OP_EQUALVERIFY
    <recipient_pubkey>
OP_ELSE
    <locktime_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
    <refund_pubkey>
OP_ENDIF
OP_CHECKSIG
```

The `OP_SIZE 32` check pins the secret to exactly 32 bytes on both chains,
which prevents the secret-length mismatch attack between chains with different
script limits. Contracts are paid to as ordinary P2SH, which has been active on
NYC since genesis, so they work today with legacy (`R...`) wallets.

## How a swap works

Alice has NYC and wants BTC. Bob has BTC and wants NYC.

| Step | Who   | Chain | Command         | What happens                                        |
| ---- | ----- | ----- | --------------- | --------------------------------------------------- |
| 1    | Both  | —     | `keygen`        | Each makes a swap key; they exchange pubkeys        |
| 2    | Alice | NYC   | `initiate`      | Makes a secret, locks NYC to Bob for **~48 h**      |
| 3    | Bob   | NYC   | `audit`         | Verifies amount, hash, his key, timelock            |
| 4    | Bob   | BTC   | `participate`   | Locks BTC to Alice, same hash, **~24 h**            |
| 5    | Alice | BTC   | `audit`         | Verifies Bob's contract                             |
| 6    | Alice | BTC   | `redeem`        | Claims BTC, which publishes the secret on-chain     |
| 7    | Bob   | BTC   | `extractsecret` | Reads the secret from Alice's redemption            |
| 8    | Bob   | NYC   | `redeem`        | Claims NYC. Done.                                   |

If either party walks away, the other runs `refund` once their timelock has
passed. The participant's timelock must be clearly shorter than the
initiator's (about half), so that Bob always has time to redeem after Alice
reveals the secret.

## Usage

Run each command against the node for the chain involved. Point `--rpcurl` at
that node, and authenticate with `--rpccookie` or `--rpcuser`/`--rpcpassword`.
Use `--rpcwallet` on multi-wallet nodes. NYC mainnet RPC defaults to
`http://127.0.0.1:17021`.

```bash
# 1. Both parties
python3 nyc_atomicswap.py keygen --state swap.json

# 2. Alice, on her NYC node
python3 nyc_atomicswap.py initiate --state swap.json --leg nyc \
  --rpccookie ~/.newyorkcoin/.cookie \
  --their-pubkey <BOB_PUBKEY> --amount 50000 --locktime-hours 48

# 3. Bob, on his NYC node (use the values Alice sent)
python3 nyc_atomicswap.py audit --state swap.json \
  --rpccookie ~/.newyorkcoin/.cookie \
  --contract <CONTRACT> --contract-tx <CONTRACT_TX> --expect-amount 50000

# 4. Bob, on his BTC node
python3 nyc_atomicswap.py participate --state swap.json --leg btc \
  --rpcurl http://127.0.0.1:8332 --rpccookie ~/.bitcoin/.cookie \
  --their-pubkey <ALICE_PUBKEY> --amount 0.001 --secret-hash <SECRET_HASH> \
  --locktime-hours 24

# 5. Alice, on her BTC node
python3 nyc_atomicswap.py audit --state swap.json \
  --rpcurl http://127.0.0.1:8332 --rpccookie ~/.bitcoin/.cookie \
  --contract <BOB_CONTRACT> --contract-tx <BOB_CONTRACT_TX> \
  --expect-amount 0.001 --expect-secret-hash <SECRET_HASH>

# 6. Alice claims the BTC
python3 nyc_atomicswap.py redeem --state swap.json \
  --rpcurl http://127.0.0.1:8332 --rpccookie ~/.bitcoin/.cookie \
  --contract <BOB_CONTRACT> --contract-tx <BOB_CONTRACT_TX>

# 7. Bob learns the secret (scans the chain for Alice's redemption)
python3 nyc_atomicswap.py extractsecret --state swap.json --leg btc \
  --rpcurl http://127.0.0.1:8332 --rpccookie ~/.bitcoin/.cookie

# 8. Bob claims the NYC (the secret is now in his state file)
python3 nyc_atomicswap.py redeem --state swap.json \
  --rpccookie ~/.newyorkcoin/.cookie \
  --contract <CONTRACT> --contract-tx <CONTRACT_TX>

# If a swap stalls: reclaim your own contract after its timelock
python3 nyc_atomicswap.py refund --state swap.json --leg nyc \
  --rpccookie ~/.newyorkcoin/.cookie
```

`--locktime-hours` is converted to blocks using each chain's measured block
time (30 s for NYC, ~10 min for BTC, ~2.5 min for LTC). Use `--locktime-blocks`
for an exact value. BIP68 caps relative locks at 65,535 blocks, which is about
22.7 days on NYC.

Every spend command accepts `--dry-run` (build and validate with
`testmempoolaccept`, but do not broadcast), `--feerate` in sat/vB, and
`--address` to pay somewhere other than a fresh wallet address.

## Safety notes

- **Back up the state file.** It holds the swap private key and, for the
  initiator, the secret. It is written with owner-only permissions. Losing it
  mid-swap means losing the ability to redeem or refund.
- **Always audit** before funding your side, and wait for confirmations on the
  counterparty's contract.
- **Redeem promptly.** After the initiator redeems, the participant must
  redeem before the initiator's timelock runs out.
- Payouts go to legacy addresses. The tool refuses SegWit payout addresses on
  chains where SegWit is not active yet, since such outputs would be
  anyone-can-spend.
- Encrypted wallets must be unlocked (`walletpassphrase`) before `initiate`
  and `participate`, because those commands fund the contract from the wallet.
- This is experimental software, like the rest of NYC Core v2. Test on regtest
  or testnet first.

## Testing

```bash
python3 contrib/atomicswap/test_regtest.py src/nycd
```

This starts two isolated regtest nodes that stand in for two chains. It runs a
full swap, a timelock refund, and consensus-level negative checks: a wrong
secret, a 31-byte secret, an early refund, a refund signed by the wrong key,
and a refund with the timelock disabled.

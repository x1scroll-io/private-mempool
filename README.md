# x1scroll Private Mempool

**Compliance-preserving confidential transactions on X1.**

The first private mempool on X1 with ZK compliance gating. Users prove they're not sanctioned (without revealing identity) → submit encrypted transactions → validators execute privately.

## How It Works

```
User → ZK Compliance Proof → Private Mempool → Tip Router → Validator
```

1. Register compliance proof (valid 1 epoch ~24hrs) — 0.00001 XNT
2. Submit encrypted transaction to private mempool — 0.00005 XNT  
3. Validator decrypts and executes — transaction never visible in public mempool
4. Optional: reveal transaction on-chain if legally required — 0.000005 XNT

## Fee Split (immutable)
- 50% → x1scroll treasury (dead fee — forever)
- 50% → burned 🔥 (deflationary on XNT)

## Program ID
`4eQRfHScBtNnB5NJvRgnFVY71hyjh1w5X1kQkdYq2uXZ` — live on X1 mainnet

## Why This Is Legal
- Compliance proof required before any private submission
- Reveal key exists — sender can prove their transaction on request
- Audit trail for regulators — just not public
- Selective disclosure, not anonymity

Built by x1scroll.io | @ArnettX1

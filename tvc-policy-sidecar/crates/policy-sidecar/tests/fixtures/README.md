# Aptos reference bytes

`aptos-transfer.hex` and `aptos-transfer-at-cap.hex` are unprefixed signing
messages generated with `aptos@1.21.0`, matching the SDK used by Turnkey's
Aptos integration when these fixtures were created. They contain
`SHA3-256("APTOS::RawTransaction") || BCS(raw_transaction)`; the domain string,
not the complete message, is hashed.

Rust unit tests compare the complete message, decoded transaction, and policy
summary. These are offline parser fixtures, not live signing requests.

| Field | Value |
| --- | --- |
| Sender | 32 zero bytes |
| Recipient | `07` repeated 32 times |
| Entry function | `0x1::aptos_account::transfer` |
| Type arguments | None |
| Sequence number | 42 |
| Transfer amount | 100,000,000 octas |
| Maximum gas | 2,000 units |
| Gas unit price | 100 octas |
| Expiration timestamp | 2,000,000,000 seconds |
| Chain ID | 2 |
| Maximum total spend | 100,200,000 octas |

The at-cap fixture changes only the amount to 999,800,000 octas, making the
maximum total exactly 1,000,000,000 octas (10 APT). Equality must be approved.
The zero sender is intentionally synthetic; a real signing request must use
a Turnkey-owned Aptos address matching the transaction sender.

To regenerate equivalent bytes, use the SDK version and fields above, serialize
a standard single-sender raw transaction, and prepend the hashed domain.
Compare the full output against each committed fixture before replacing it.
Node.js and the Aptos SDK are not required to build or test this Rust example.

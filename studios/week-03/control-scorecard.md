# Week 3 Control Scorecard

| Construction | Guarantee (axis 2) | Condition / failure | Classification |
|---|---|---|---|
| ECB | Confidentiality of each individual block, provided an attacker does not need message-level pattern hiding. | Identical plaintext blocks produce identical ciphertext blocks, so repeated structure is visible. | Mode misuse; the block cipher is not broken. |
| CBC / CTR | Message confidentiality when the mode's state is used correctly. | CBC requires a fresh, unpredictable IV; CTR requires a nonce that never repeats under the same key. Reusing a CTR nonce creates a two-time pad and reveals plaintext relationships. | Mode misuse; the block cipher is not broken. |
| `H(secret || msg)` MAC | It appears to authenticate a message only if the hash does not expose a resumable state; Merkle-Damgard hashes do expose it. | Length extension lets an attacker append data and forge a valid tag without knowing the secret. | Construction misuse; the hash primitive is not broken. |
| HMAC | Message authentication, provided the key remains secret and verification compares the complete tag securely. | The nested construction hides the internal hash state, so the demonstrated length-extension attack does not apply. | No primitive break; HMAC is the appropriate construction. |

All observed failures are caused by misuse of a mode or construction, not by a
break of the underlying cipher or hash primitive.

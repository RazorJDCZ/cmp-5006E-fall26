# Week 4 Control Scorecard

| Control | Guarantee (axis 2) | Condition outside the algorithm | Evidence from the studio |
|---|---|---|---|
| RSA-2048 | Factoring a correctly generated modulus `n = p * q` is computationally infeasible, so deriving the private exponent from the public key is infeasible. | `p` and `q` must be generated with sufficient entropy and independently for every key. | Two individually plausible public keys shared a prime. Computing `gcd(n_i, n_j)` exposed that prime and allowed both private exponents to be recovered without factoring a strong modulus. |
| Secret comparison | Comparing a submitted value with a secret should reveal only whether they are equal. | The implementation must examine the complete inputs without data-dependent early exits; production code should use `hmac.compare_digest`. | The early-exit comparison leaked the matching-prefix length through its duration, allowing the secret to be recovered byte by byte. The constant-time implementation removed that timing signal. |

The failures do not break RSA's mathematics or the equality operation. They
break environmental and implementation conditions that those guarantees rely
on: independent randomness and constant-time secret handling.

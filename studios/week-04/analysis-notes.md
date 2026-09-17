# Week 4 Analysis Notes

## Shared-factor scan cost

For a corpus of `k` public keys, the implemented pairwise scan checks every
unordered pair, so it performs

```text
k(k - 1) / 2
```

GCD calculations. Its asymptotic cost is therefore `O(k^2)`. This is adequate
for the eight-key studio corpus, but it is not the method used for an
internet-scale collection. A batch-GCD algorithm based on product and remainder
trees reuses the large multiplications and reductions across the corpus, making
the scan near-linear (apart from big-integer arithmetic costs). That is why a
scan of millions of public moduli can remain practical.

## Timing measurements

The attack uses the provided default of **41 interleaved rounds per candidate**.
Interleaving all 256 candidates on each round spreads scheduler delays and CPU
frequency drift across the candidate set. Taking the median then suppresses
occasional outliers. With the studio's amplified per-byte work, 41 rounds gives
a stable enough signal to recover the supplied two-byte secret in the provided
tests.

The recovered timing signal is not evidence that the secret or RSA primitive
was mathematically weak. It comes from `insecure_equal` returning after the
first mismatching byte: a correct candidate prefix performs one more unit of
work and therefore tends to have the largest median duration.

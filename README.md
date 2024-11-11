# fast pda grinder

When doing something like (pseudocode)
```rust
loop {
    let seed = random_seed();
    let pubkey = find_pda(&[&seed], &program);
    let bs58 = pubkey.to_string();
    let matches = bs58.starts_with(target);
}
```
a quick look at performance counters will show that the offcurve evaluation is the most expensive portion of this calculation. At a high level, the following filters are being applied to a candidate output of a random sha256 hash:

1) Is this hash off-curve? (very expensive)
2) Does this off-curve hash, when bs58 encoded, start with my target string (somewhat expensive)

But... we can invert these filters! We can encode `LOOK_AHEAD_WINDOW` (default = 1) hashes assuming bump seed is in `(255 - LOOK_AHEAD_WINDOW + 1)..=255`, and see if any of these hashes, when bs58 encoded, start with a target string. Then, we move on to the expensive
check to see if any of them were valid pdas[^1].


[^1]: The most optimal `LOOK_AHEAD_WINDOW` is 1, since the first bump has a 50% chance
of being a PDA. Spending additional compute on 254, for example, means you are spending time computing and encoding a sha256 hash that only has a 25% probability of being a PDA instead of some other hash that has a 50% probability.


## Usage
To grind:

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin fixed \
    -- grind \
    --owner <PROGRAM_ID> \
    --target TEMPo \
    --threads <NUM_THREADS>
```

To verify (mostly for my debugging, but this uses `Pubkey::find_program_address(.., ..)` directly):

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release --bin fixed \
    -- check \
    --owner <PROGRAM_ID> \
    --seed <YOUR_U64_SEED>
```



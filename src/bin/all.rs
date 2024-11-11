use std::{
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[cfg(feature = "timers")]
use std::time::Duration;

use clap::Parser;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

#[derive(Parser)]
pub enum Command {
    Grind(GrindArgs),
    Check(CheckArgs),
}
#[derive(Debug, Parser)]
pub struct GrindArgs {
    #[clap(long, value_parser = parse_pubkey)]
    pub owner: Pubkey,

    /// NOT CHECKED FOR BS58 RN
    #[clap(long)]
    pub target: String,

    #[clap(long, default_value_t = 1)]
    pub threads: u64,
}

#[derive(Debug, Parser)]
pub struct CheckArgs {
    #[clap(long, value_parser = parse_pubkey)]
    pub owner: Pubkey,

    #[clap(long)]
    pub seed: u64,
}

fn parse_pubkey(s: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(s).map_err(|e| e.to_string())
}

const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

static MATCHES: AtomicU64 = AtomicU64::new(0);

macro_rules! with_timer {
    ($whatever:stmt) => {
        #[cfg(feature = "timers")]
        {
            $whatever
        }
    };
}

fn main() {
    let command = Command::parse();

    let args = match command {
        Command::Grind(args) => args,
        Command::Check(CheckArgs { owner, seed }) => {
            println!(
                "seed {seed} for owner {owner} gives key {}",
                Pubkey::find_program_address(&[&seed.to_le_bytes()], &owner).0
            );
            return;
        }
    };

    println!(
        "looking for u64 seeds that give {}... for program {}",
        &args.target, args.owner
    );

    // Shared offset across threads
    let offset = rand::random::<u64>();

    let handles = (0..args.threads)
        .map(|i| {
            let target = args.target.clone();
            std::thread::Builder::new()
                .stack_size(512)
                .spawn(move || {
                    let mut seed = (u64::MAX / 32 * i).wrapping_add(offset);

                    // 8-byte aligned 62-byte buffer
                    //
                    // Note: we only use 62 bytes!
                    // [u64 seed][u8 bump][32 byte owner key][21 byte PDA_MARKER]
                    // 8 + 1 + 32 + 21 = 62
                    let mut buffer = [0_u64; 8];
                    let buffer_ptr: *mut u8 = buffer.as_mut_ptr().cast();
                    // Write in owner, and pda marker
                    unsafe {
                        let owner_ptr: *mut Pubkey = buffer_ptr.add(9).cast();
                        *owner_ptr = args.owner;

                        let marker_ptr: *mut [u8; 21] = buffer_ptr.add(41).cast();
                        *marker_ptr = *PDA_MARKER;
                    }

                    let set_bump = {
                        #[inline(always)]
                        |buffer_ptr: *mut u8, offset: u8| unsafe {
                            let pda_ptr: *mut u8 = buffer_ptr.add(8);
                            *pda_ptr = u8::MAX - offset;
                        }
                    };

                    let set_seed = {
                        #[inline(always)]
                        |buffer_ptr: *mut u8, seed: u64| unsafe {
                            let seed_ptr: *mut u64 = buffer_ptr.cast();
                            *seed_ptr = seed;
                        }
                    };

                    let get_preimage = {
                        #[inline(always)]
                        |buffer_ptr: *mut u8| -> &[u8; 62] { unsafe { &*buffer_ptr.cast() } }
                    };

                    let is_cpu0 = i == 0;
                    let timer = Instant::now();

                    let mut hash_bytes = [0; 32];
                    let mut bs58_bytes = [0; 44];

                    with_timer!(let mut hash_time = Duration::default());
                    with_timer!(let mut bs58_time = Duration::default());
                    with_timer!(let mut offc_time = Duration::default());
                    for l in 1.. {
                        for _ in 0..1_000_000 {
                            seed += 1;
                            set_seed(buffer_ptr, seed);

                            'bump: for bump_offset in 0..u8::MAX {
                                // Hash to get candidate address
                                set_bump(buffer_ptr, bump_offset);

                                with_timer!(let hash_timer = Instant::now());
                                Sha256::new()
                                    .chain_update(get_preimage(buffer_ptr))
                                    .finalize_into((&mut hash_bytes).into());
                                with_timer!(hash_time += hash_timer.elapsed());

                                // Check if candidate address is off-curve
                                with_timer!(let offc_timer = Instant::now());
                                let key: &Pubkey = unsafe { &*hash_bytes.as_ptr().cast() };
                                let is_off_curve = !key.is_on_curve();
                                with_timer!(offc_time += offc_timer.elapsed());

                                if is_off_curve {
                                    // base58 encode
                                    with_timer!(let bs58_timer = Instant::now());
                                    let len = five8::encode_32(&hash_bytes, &mut bs58_bytes);
                                    with_timer!(bs58_time += bs58_timer.elapsed());

                                    let key_bs58 = unsafe {
                                        core::str::from_utf8_unchecked(
                                            bs58_bytes.get_unchecked(..len as usize),
                                        )
                                    };
                                    if key_bs58.starts_with(&target) {
                                        println!("core {i} found {key_bs58} with seed {seed}");
                                        MATCHES.fetch_add(1, Ordering::Relaxed);
                                    }
                                    break 'bump;
                                }
                            }
                        }

                        if is_cpu0 {
                            #[cfg(feature = "timers")]
                            println!(
                                "core 0 finished {} iters in {}s; hash {}; bs58 {}; offc {}; matches {}",
                                l * 1_000_000,
                                timer.elapsed().as_secs(),
                                hash_time.as_secs(),
                                bs58_time.as_secs(),
                                offc_time.as_secs(),
                                MATCHES.load(Ordering::Relaxed),
                            );
                            #[cfg(not(feature = "timers"))]
                            println!(
                                "core 0 finished {} iters in {}s; matches {}",
                                l * 1_000_000,
                                timer.elapsed().as_secs(),
                                MATCHES.load(Ordering::Relaxed),
                            );
                        }
                    }
                })
                .unwrap()
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }
}

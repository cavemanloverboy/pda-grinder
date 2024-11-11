use std::{
    fs::File,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
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
static TOTAL_ITERS: AtomicU64 = AtomicU64::new(0);

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

    let seeds = Arc::new(Mutex::new(
        File::options()
            .create(true)
            .append(true)
            .write(true)
            .open("results.txt")
            .unwrap(),
    ));
    #[inline(always)]
    fn add_seed(arcm_file: &Arc<Mutex<File>>, key: &Pubkey, seed: u64) {
        use std::io::Write;
        writeln!(&mut *arcm_file.lock().unwrap(), "{key}: {seed}").unwrap();
    }

    let handles = (0..args.threads)
        .map(|i| {
            let target = args.target.clone();
            let arcm_seeds = Arc::clone(&seeds);
            std::thread::Builder::new()
                .stack_size(512)
                .spawn(move || {
                    let mut seed = (u64::MAX / args.threads * i).wrapping_add(offset);

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

                    with_timer!(let mut hash_time = Duration::default());
                    with_timer!(let mut bs58_time = Duration::default());
                    with_timer!(let mut offc_time = Duration::default());

                    const LOOK_AHEAD_WINDOW: usize = 1;

                    const ITER_BATCH_SIZE: u64 = 1_000_000;

                    for l in 1.. {
                        'inner: for _ in 0..ITER_BATCH_SIZE {
                            seed += 1;
                            set_seed(buffer_ptr, seed);

                            // Calculate first 8 candidate addresses
                            let mut candidate_addresses = [[0_u8; 32]; LOOK_AHEAD_WINDOW];
                            let mut candidate_addresses_bs58 = [[0_u8; 44]; LOOK_AHEAD_WINDOW];
                            let mut candidate_addresses_bs58_len = [0_usize; LOOK_AHEAD_WINDOW];
                            let mut matches = [false; LOOK_AHEAD_WINDOW];
                            for bump_offset in 0..LOOK_AHEAD_WINDOW as u8 {
                                // Set bump
                                set_bump(buffer_ptr, bump_offset);

                                // Calculate hash
                                with_timer!(let hash_timer = Instant::now());
                                Sha256::new()
                                    .chain_update(get_preimage(buffer_ptr))
                                    .finalize_into(
                                        (&mut candidate_addresses[bump_offset as usize]).into(),
                                    );
                                with_timer!(hash_time += hash_timer.elapsed());

                                // Encode hash and cache bs58 length
                                with_timer!(let bs58_timer = Instant::now());
                                candidate_addresses_bs58_len[bump_offset as usize] =
                                    five8::encode_32(
                                        &candidate_addresses[bump_offset as usize],
                                        &mut candidate_addresses_bs58[bump_offset as usize],
                                    ) as usize;
                                with_timer!(bs58_time += bs58_timer.elapsed());

                                // Check if we have target string
                                let candidate_str: &str = unsafe {
                                    core::str::from_utf8_unchecked(
                                        &candidate_addresses_bs58[bump_offset as usize]
                                            [..candidate_addresses_bs58_len[bump_offset as usize]],
                                    )
                                };
                                matches[bump_offset as usize] = candidate_str.starts_with(&target);
                            }

                            if matches.iter().any(|m| *m) {
                                // Go down the line and see which is the first off curve address,
                                // and see if this one was a match
                                let mut found_off_curve = false;
                                for i in 0..LOOK_AHEAD_WINDOW {
                                    // Is this off curve?
                                    let key: &Pubkey =
                                        unsafe { &*candidate_addresses.as_ptr().add(i).cast() };

                                    with_timer!(let offc_timer = Instant::now());
                                    found_off_curve |= !key.is_on_curve();
                                    with_timer!(offc_time += offc_timer.elapsed());

                                    if found_off_curve {
                                        if matches[i] {
                                            // We have a match!
                                            println!("found {key} with seed {seed}");
                                            add_seed(&arcm_seeds, key, seed);
                                            MATCHES.fetch_add(1, Ordering::Relaxed);
                                        }
                                        continue 'inner;
                                    }
                                }
                            }
                        }

                        if is_cpu0 {
                            let other_iters = TOTAL_ITERS.load(Ordering::Relaxed);
                            let my_iters = l * ITER_BATCH_SIZE;
                            let total_iters = other_iters + my_iters;
                            #[cfg(feature = "timers")]
                            println!(
                                "{} iters in {}s; hash {}; bs58 {}; offc {}; matches {}",
                                total_iters,
                                timer.elapsed().as_secs(),
                                hash_time.as_secs(),
                                bs58_time.as_secs(),
                                offc_time.as_secs(),
                                MATCHES.load(Ordering::Relaxed),
                            );
                            #[cfg(not(feature = "timers"))]
                            println!(
                                "{} iters in {}s; matches {}",
                                total_iters,
                                timer.elapsed().as_secs(),
                                MATCHES.load(Ordering::Relaxed),
                            );
                        } else {
                            TOTAL_ITERS.fetch_add(ITER_BATCH_SIZE, Ordering::Relaxed);
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

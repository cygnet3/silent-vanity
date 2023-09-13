use std::{str::FromStr, sync::mpsc, thread, time::Instant};

use bdk::{
    bitcoin::{
        secp256k1::Secp256k1,
        util::bip32::DerivationPath,
        Network,
    },
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, GeneratableKey, GeneratedKey,
    },
    miniscript,
};
use bech32::ToBase32;
use clap::Parser;
use silentpayments::receiving::Receiver;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// String to look for
    #[arg(long)]
    name: String,

    /// Number of threads to use
    #[arg(long, default_value_t = 1)]
    num_threads: u8,

    /// Type of network. Options: bitcoin, testnet, signet, regtest
    #[arg(long)]
    network: Network,
}

fn main() {
    let args = Args::parse();

    let is_testnet = args.network != Network::Bitcoin;
    let (scan_path, spend_path) = match is_testnet {
        true => ("m/352h/1h/0h/1h/0", "m/352h/1h/0h/0h/0"),
        false => ("m/352h/0h/0h/1h/0", "m/352h/0h/0h/0h/0"),
    };

    let scan_path: DerivationPath = DerivationPath::from_str(scan_path).unwrap();
    let spend_path: DerivationPath = DerivationPath::from_str(spend_path).unwrap();

    let network = args.network;
    eprintln!("network: {:?}", network);

    let (tx, rx) = mpsc::channel();
    let num_threads = args.num_threads;
    println!("Using {} threads", num_threads);

    let (_, target) = bech32::decode_without_checksum(format!("a1{}", args.name).as_str()).unwrap();

    let startchars = "gf2tvdw0";
    let firstchar = args.name.chars().next().unwrap();

    let present = startchars.contains(firstchar);

    if present {
        println!("Starting character is present in list 'gf2tvdw0'!");
    } else {
        println!("Starting character is not present in list 'gf2tvdw0'.");
    }

    // eprintln!("target = {:?}", target);
    let (is, ie) = if present {
        (1, 1 + target.len())
    } else {
        (2, 2 + target.len())
    };

    let start = Instant::now();

    for i in 0..num_threads {
        let secp = Secp256k1::new();
        let tx = tx.clone();
        let scan_path = scan_path.clone();
        let spend_path = spend_path.clone();
        let target = target.clone();

        thread::spawn(move || {
            loop {
                let mnemonic: GeneratedKey<_, miniscript::Segwitv0> =
                    Mnemonic::generate((WordCount::Words12, Language::English)).unwrap();
                let xprv = mnemonic
                    .clone()
                    .into_extended_key()
                    .unwrap()
                    .into_xprv(network)
                    .unwrap();
                let sk = xprv.derive_priv(&secp, &scan_path).unwrap().private_key;
                let pk = sk.public_key(&secp);
                let pkeybytes = pk.serialize().to_vec().to_base32();

                let bytes = &pkeybytes[is..ie];

                if bytes == &target[..] {
                    eprintln!("mnemonic = {:?}", mnemonic.to_string());

                    let secp = Secp256k1::new();
                    let bob_scan_key = xprv.derive_priv(&secp, &scan_path).unwrap().private_key;
                    let bob_spend_key = xprv.derive_priv(&secp, &spend_path).unwrap().private_key;
                    let receiver =
                        Receiver::new(0, bob_scan_key, bob_spend_key, is_testnet).unwrap();

                    eprintln!("receiving address: {:?}", receiver.get_receiving_address());
                    tx.send(i).unwrap();
                    return;
                }
                // thread::sleep(Duration::from_millis(100));
            }
        });
    }

    // Wait for a message from any thread
    let _thread_id = rx.recv().unwrap();
    // println!("Thread {} found result.", thread_id);

    // Capture the time after the threads are done
    let duration = start.elapsed();

    // Print the elapsed time
    println!("Time elapsed: {:?}", duration);
}

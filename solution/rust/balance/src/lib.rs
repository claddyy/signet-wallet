#![allow(unused)]

use std::convert::TryInto;
use std::process::Command;

use bitcoincore_rpc::jsonrpc::serde_json::{from_slice, Value};
use bs58::decode;
use hmac_sha512::HMAC;
use num_bigint::BigUint;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

// Provided by administrator
pub const WALLET_NAME: &str = "wallet_152";
pub const EXTENDED_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPdisufuN1WwxfQGPpBAm9DD11kyTANuq8LDBh6nGFj1kaddVP5U9if6LypPkdnUkuxLMUFkEyMNDSreXx12hxJC6WsboYbbs";

#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // Add relevant error variants for various cases.
}

#[derive(Clone,Debug)]
struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 32],
}

// final wallet state struct
#[derive(Clone)]
pub struct WalletState {
    utxos: Vec<Vec<u8>>,
    witness_programs: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
    private_keys: Vec<Vec<u8>>,
}

impl WalletState {
    // Given a WalletState find the balance is satoshis
    pub fn balance(&self) -> f64 {
        let mut total_balance: f64 = 0.0;
        for utxo in &self.utxos {
            let ut = String::from_utf8(utxo.to_vec()).unwrap();
            let parts: Vec<&str> = ut.split(':').collect();
            let txid = parts[0];
            let vout: usize = parts[1].parse().unwrap();

            let tx_data = bcli(&format!("getrawtransaction {} 1", txid)).unwrap();
            let tx: Value = from_slice(&tx_data).unwrap();

            if let Some(output) = tx["vout"].get(vout) {
                let output_value = output["value"].as_f64().unwrap();
                total_balance += output_value;
            } else {
                return 0.0;
            }
        }
        total_balance
    }
}

// Decode a base58 string into an array of bytes
fn base58_decode(base58_string: &str) -> Vec<u8> {
    let base58_alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Convert Base58 string to a big integer

    let mut num =  BigUint::from(0_u32);
    for c in base58_string.bytes() {
        num *= 58_u32;
        let el = base58_alphabet.iter().position(|x| c == *x).unwrap();
        num += el;
    }
    // println!("{}",num);
    let combined = num.to_bytes_be();
    let checksum: Vec<u8> = combined.clone().into_iter().rev().take(4).collect();
    let head: Vec<u8> = combined.clone().into_iter().take(combined.len()-4).to_owned().collect();
    let hash256: Vec<u8> = Sha256::digest(Sha256::digest(head.clone())).to_vec().into_iter().take(4).rev().collect();

    // println!("Checksum {:?}",checksum);
    // println!("Hash256 {:?}",hash256);
    if hash256 != checksum {
        panic!("Bad address:{:?} {:?}",checksum,hash256)
    }
    head
    // Convert the integer to bytes
    // Chop off the 32 checksum bits and return
    // BONUS POINTS: Verify the checksum!
    // unimplemented!("implement the logic")
}

// Deserialize the extended pubkey bytes and return a ExKey object
// Bip32 Serialization format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
// 32 bytes: the chain code
// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
fn deserialize_key(bytes: &[u8]) -> ExKey {
    let key = ExKey {
        version: bytes[0..4].try_into().unwrap(),
        depth: bytes[4..5].try_into().unwrap(),
        finger_print: bytes[5..9].try_into().unwrap(),
        child_number: bytes[9..13].try_into().unwrap(),
        chaincode: bytes[13..45].try_into().unwrap(),
        key: bytes[46..].try_into().unwrap(),
    };

    key
}

// Derive the secp256k1 compressed public key from a given private key
// BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!
fn derive_public_key_from_private(key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(key).expect("Invalid Private Key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let compressed_public_key = public_key.serialize();

    compressed_public_key.to_vec()
}

// Perform a BIP32 parent private key -> child private key derivation
// Return a derived child Xpriv, given a child_number. Check the struct docs for APIs.
// Key derivation steps: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
fn derive_priv_child(key: ExKey, child_num: u32) -> ExKey {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&key.key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let finger_print = &Ripemd160::digest(Sha256::digest(&public_key.serialize()))[0..4];

    let data = if child_num >= 0x80000000 {
        let mut data = Vec::new();
        data.push(0);
        data.extend_from_slice(&key.key);
        data.extend_from_slice(&child_num.to_be_bytes());
        data
    } else {
        let mut data = public_key.serialize().to_vec();
        data.extend_from_slice(&child_num.to_be_bytes());
        data
    };

    let hmac = HMAC::mac(&data, &key.chaincode);
    let child_key_slice = SecretKey::from_slice(&hmac[..32]).unwrap();
    let child_chaincode = &hmac[32..];

    let child_skey = secret_key
        .add_tweak(&Scalar::from(child_key_slice))
        .unwrap();

    ExKey {
        version: key.version,
        depth: [key.depth[0] + 1],
        finger_print: finger_print.try_into().unwrap(),
        child_number: child_num.to_be_bytes(),
        chaincode: child_chaincode.try_into().unwrap(),
        key: child_skey[0..32].try_into().unwrap(),
    }
}

// Given an extended private key and a BIP32 derivation path, compute the child private key found at the path
// Derivation paths are strings like "m/0'/1/2h/2"
fn get_child_key_at_path(key: ExKey, derivation_path: &str) -> ExKey {
    let mut currkey = key.clone();
    for segment in derivation_path.split("/") {
        let harderned = segment.ends_with("'") || segment.ends_with("h");
        let index_str = segment.trim_end_matches("'").trim_end_matches("h");
        let index = index_str.parse::<u32>().unwrap();
        let child_num = if harderned { index | 0x80000000 } else { index };
        currkey = derive_priv_child(currkey, child_num);
    }
    currkey
}

// Compute the first N child private keys.
// Return an array of keys.
fn get_keys_at_child_key_path(child_key: ExKey, num_keys: u32) -> Vec<ExKey> {
    let mut keys = Vec::new();
    for i in 0..num_keys {
        let key = derive_priv_child(child_key.clone(), i);
        keys.push(key);
    }
    keys
}

// Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key
// Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
// so we can find our received transactions in blocks
// These are segwit version 0 pay-to-public-key-hash witness programs
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    let hash = Ripemd160::digest(Sha256::digest(pubkey));
    let mut program = Vec::new();
    program.push(0x00);
    program.extend_from_slice(&[hash.len() as u8]);
    program.extend_from_slice(&hash);

    program
}

// Assuming Bitcoin Core is running and connected to signet using default datadir,
// execute an RPC and return its value or error message.
// https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
// Examples: bcli("getblockcount")
//            bcli("getblockhash 100")
fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let args = cmd.split(' ').collect::<Vec<&str>>();

    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;

    return if result.status.success() {
        Ok(result.stdout)
    } else {
        Ok(result.stderr)
    };
}

// public function that will be called by `run` here as well as the spend program externally
pub fn recover_wallet_state(
    extended_private_key: &str,
    cookie_filepath: &str,
) -> Result<WalletState, BalanceError> {
    // Deserialize the provided extended private key
    let decoded_key = base58_decode(extended_private_key);
    let deserialized_key = deserialize_key(&decoded_key);
    // Derive the key and chaincode at the path in the descriptor (`84h/1h/0h/0`)
    let path = "84h/1h/0h/0";
    // Get the child key at the derivation path
    let child_key = get_child_key_at_path(deserialized_key, path);
    // Compute 2000 private keys from the child key path
    let derived_keys = get_keys_at_child_key_path(child_key, 2000);
    // For each private key, collect compressed public keys and witness programs
    let mut private_keys: Vec<Vec<u8>> = vec![];
    let mut public_keys = vec![];
    let mut witness_programs = vec![];

    for event in derived_keys {
        let private_key = event.key;
        let public_key = derive_public_key_from_private(&private_key);
        let witness_program = get_p2wpkh_program(&public_key);
        private_keys.push(private_key.try_into().unwrap());
        public_keys.push(public_key);
        witness_programs.push(witness_program);
    }

    // Collect outgoing and spending txs from a block scan
    let mut outgoing_txs: Vec<Vec<u8>> = vec![];
    let mut spending_txs: Vec<Vec<u8>> = vec![];
    let mut utxos: Vec<Vec<u8>> = vec![];

    // Scan blocks 0 to 300 for transactions
    for height in 0..310 {
        let block_hash = bcli(&format!("getblockhash {}", height)).unwrap();
        let block_data = bcli(&format!(
            "getblock {} 2",
            String::from_utf8(block_hash).unwrap().trim()
        ))
            .unwrap();

        let block: Value = from_slice(&block_data).unwrap();
        let transactions = block["tx"].as_array().unwrap().clone();

        for tx in transactions {
            let inputs = tx["vin"].as_array().unwrap();
            let mut flag = 0;
            for input in inputs {
                if let Some(witness) = input["txinwitness"].as_array() {
                    if let Some(pubkey) = witness.get(1) {
                        let pubkey_bytes = hex::decode(pubkey.as_str().unwrap()).unwrap();
                        if public_keys.contains(&pubkey_bytes) {
                            flag = 1;
                            break;
                        }
                    }
                }
            }
            if (flag == 1) {
                spending_txs.push(hex::decode(tx["txid"].as_str().unwrap()).unwrap());
            }
            let outputs = tx["vout"].as_array().unwrap();
            for output in outputs {
                if let Some(script_pub_key) = output["scriptPubKey"]["hex"].as_str() {
                    let script_bytes = hex::decode(script_pub_key).unwrap();
                    if witness_programs.contains(&script_bytes) {
                        flag = 2;
                        break;
                    }
                }
            }
            if (flag == 2) {
                outgoing_txs.push(hex::decode(tx["txid"].as_str().unwrap()).unwrap());
            }
        }
    }
    // Check every tx input (witness) for our own compressed public keys. These are coins we have spent.
    // Check every tx output for our own witness programs. These are coins we have received.
    // Keep track of outputs by their outpoint so we can check if it was spent later by an input
    // Collect outputs that have not been spent into a utxo set
    // Return Wallet State
    for tx_hash in &outgoing_txs {
        let tx_data = bcli(&format!("getrawtransaction {} 1", hex::encode(tx_hash))).unwrap();
        let tx: Value = from_slice(&tx_data).unwrap();
        let txid = tx["txid"].as_str().unwrap();
        let outputs = tx["vout"].as_array().unwrap();
        for (index, output) in outputs.iter().enumerate() {
            if let Some(script_pub_key) = output["scriptPubKey"]["hex"].as_str() {
                let script_bytes = hex::decode(script_pub_key).unwrap();
                if witness_programs.contains(&script_bytes) {
                    utxos.push(format!("{}:{}", txid, index).into_bytes());
                }
            }
        }
    }

    Ok(WalletState {
        utxos,
        public_keys,
        private_keys,
        witness_programs,
    })
}

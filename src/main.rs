//! A simple command-line tool for encrypting and decrypting strings using AES encryption.

use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::env;

fn main() {
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check if the required arguments are provided
    if args.len() < 3 {
        println!("Usage: {} <string> <password> [-d]", args[0]);
        return;
    }

    // Extract the string, password, and decryption flag from the arguments
    let string = &args[1];
    let password = &args[2];
    let decrypt = args.len() > 3 && args[3] == "-d";

    // Generate a 256-bit key from the password using SHA-256
    let mut hasher = Sha256::new();
    hasher.input_str(password);
    let key = hasher.result_str()[..32].to_string();

    // Perform encryption or decryption based on the flag
    if decrypt {
        let decrypted_string = decrypt_string(string, &key);
        println!("Decrypted string: {}", decrypted_string);
    } else {
        let encrypted_string = encrypt_string(string, &key);
        println!("Encrypted string: {}", encrypted_string);
    }
}

/// Encrypts the given string using AES encryption with the provided key.
///
/// The string is padded with spaces to ensure its length is a multiple of the block size (16 bytes).
/// The encrypted string is returned as a hexadecimal representation.
fn encrypt_string(string: &str, key: &str) -> String {
    let block_size = 16;
    let mut padded_string = string.to_string();
    let padding_length = block_size - (string.len() % block_size);
    padded_string.extend(std::iter::repeat(' ').take(padding_length));

    let mut encryptor = crypto::aes::ecb_encryptor(
        crypto::aes::KeySize::KeySize256,
        key.as_bytes(),
        crypto::blockmodes::PkcsPadding,
    );

    let mut encrypted_bytes = vec![0; padded_string.len()];
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(padded_string.as_bytes());
    let mut buffer = crypto::buffer::RefWriteBuffer::new(&mut encrypted_bytes);
    encryptor
        .encrypt(&mut read_buffer, &mut buffer, true)
        .unwrap();
    hex::encode(buffer.take_read_buffer().take_remaining())
}

/// Decrypts the given encrypted string using AES decryption with the provided key.
///
/// The encrypted string is expected to be a hexadecimal representation of the encrypted bytes.
/// The decrypted string is returned as a plain string with any padding removed.
fn decrypt_string(encrypted_string: &str, key: &str) -> String {
    let mut decryptor = crypto::aes::ecb_decryptor(
        crypto::aes::KeySize::KeySize256,
        key.as_bytes(),
        crypto::blockmodes::NoPadding,
    );

    let encrypted_bytes = hex::decode(encrypted_string).unwrap();
    let mut decrypted_bytes = vec![0; encrypted_bytes.len()];
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(&encrypted_bytes);
    let mut buffer = crypto::buffer::RefWriteBuffer::new(&mut decrypted_bytes);
    decryptor
        .decrypt(&mut read_buffer, &mut buffer, true)
        .unwrap();
    String::from_utf8(buffer.take_read_buffer().take_remaining().to_vec()).unwrap()
}

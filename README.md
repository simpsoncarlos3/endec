# endec

A simple command-line tool for encrypting and decrypting strings using AES encryption with a password.

## Features

- Encrypts strings using AES encryption with a 256-bit key derived from a password
- Decrypts encrypted strings using the same password
- Supports encryption and decryption modes
- Provides a simple and intuitive command-line interface

## Installation

To install `endec`, you need to have Rust and Cargo installed on your system. If you don't have them already, you can download and install Rust from the official website: <https://www.rust-lang.org/tools/install>

Once you have Rust and Cargo set up, you can install `endec` by running the following command:
`cargo install endec`

This command will download the `endec` crate from crates.io and compile it, generating an executable binary. The binary will be installed into the installation root's `bin` directory, which is typically `$HOME/.cargo/bin` on Unix-like systems and `%USERPROFILE%\.cargo\bin` on Windows.

Make sure that the installation root's `bin` directory is in your system's `PATH` environment variable so that you can run the `endec` command from anywhere in the terminal.

## Usage

To use `endec`, open a terminal and run the following command:
`endec <string> <password> [-d]`

- `<string>`: The string to encrypt or decrypt.
- `<password>`: The password to use for encryption or decryption.
- `-d`: An optional flag to specify decryption mode. If not provided, encryption mode is used.

### Encryption

To encrypt a string, provide the string and password as arguments to the `endec` command:
`endec "Hello, World!" mypassword`

The encrypted string will be displayed in the terminal:
`Encrypted string: 1b4fb22942d0e22a5c0c2c3e2d3f4a5b`

### Decryption

To decrypt an encrypted string, provide the encrypted string, password, and the `-d` flag to the `endec` command:
`endec 1b4fb22942d0e22a5c0c2c3e2d3f4a5b mypassword -d`

The decrypted string will be displayed in the terminal:
`Decrypted string: Hello, World!`

## Security Considerations

- The encryption key is derived from the provided password using SHA-256. While this provides a basic level of security, it is recommended to use strong, unique passwords for each encryption.
- The encrypted strings are encoded in hexadecimal format for easy transmission and storage. However, it is important to store and transmit the encrypted strings securely to prevent unauthorized access.
- AES encryption is used in ECB mode, which may not be suitable for all use cases. Consider using other modes like CBC or GCM for enhanced security, depending on your specific requirements.

## License

This project is licensed under the [MIT License](LICENSE) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the [GitHub repository](https://github.com/simpsoncarlos3/endec).

## Disclaimer

This tool is provided as-is and is intended for educational and informational purposes only. The authors and contributors are not responsible for any misuse, damage, or illegal activities resulting from the use of this tool. Use it responsibly and at your own risk.

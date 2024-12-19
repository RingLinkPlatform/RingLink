/*
 * Copyright 2024 RingNet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

use bytes::BytesMut;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::error::Result;
use ringlink_identity::PublicIdentity;

const AAD: &str = "ringlink-crypto";
const TAG_LEN: usize = 16;
pub const IV_LEN: usize = 12;

/// Encrypt data with ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - secret key
/// * `data` - data to encrypt
///
/// # Returns
/// * `Ok((encrypted_data, iv))` - encrypted data and iv
pub fn encrypt(key: &[u8], data: &[u8]) -> Result<(BytesMut, [u8; IV_LEN])> {
    let mut iv = [0u8; IV_LEN];
    openssl::rand::rand_bytes(&mut iv)?;

    let t = Cipher::chacha20_poly1305();
    let mut out = BytesMut::zeroed(TAG_LEN + data.len() + t.block_size());

    let mut c = Crypter::new(t, Mode::Encrypt, &key, Some(&iv))?;
    c.aad_update(AAD.as_bytes())?;

    let count = c.update(&data, &mut out[TAG_LEN..])?;
    let rest = c.finalize(&mut out[TAG_LEN + count..])?;

    c.get_tag(&mut out[..TAG_LEN])?;
    out.truncate(TAG_LEN + count + rest);

    Ok((out, iv))
}

/// Decrypt data with ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - secret key
/// * `data` - data to decrypt
/// * `iv` - iv used to encrypt data
///
/// # Returns
/// * `Ok(decrypted_data)` - decrypted data
pub fn decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<BytesMut> {
    debug_assert!(data.len() > TAG_LEN);

    let t = Cipher::chacha20_poly1305();
    let mut out = BytesMut::zeroed(data.len() + t.block_size());

    let mut c = Crypter::new(t, Mode::Decrypt, &key, Some(&iv))?;
    c.aad_update(AAD.as_bytes())?;

    let count = c.update(&data[TAG_LEN..], &mut out)?;
    c.set_tag(&data[..TAG_LEN])?;
    let rest = c.finalize(&mut out[count..])?;

    out.truncate(count + rest);

    Ok(out)
}

/// Verify signature with public identity
///
/// # Arguments
/// * `identity` - public identity
/// * `data` - data to verify
/// * `signature` - signature to verify
///
/// # Returns
///
/// On success, returns `Ok(true)`, otherwise `Ok(false)` or `Err`
#[allow(dead_code)]
pub fn verify(
    identity: &PublicIdentity,
    data: impl AsRef<[u8]>,
    signature: impl AsRef<[u8]>,
) -> Result<bool> {
    Ok(identity.verify(data, signature)?)
}

#[cfg(test)]
mod test {
    use crate::crypto::{decrypt, encrypt};
    use std::time::Instant;

    #[test]
    fn test_enc() {
        let key = [0u8; 32];
        let data = b"hello world";

        let start = Instant::now();
        let (enc, iv) = encrypt(&key, data).unwrap();
        dbg!(start.elapsed());

        let dec = decrypt(&key, &enc, &iv).unwrap();

        assert_eq!(data, dec.as_ref());
    }
}

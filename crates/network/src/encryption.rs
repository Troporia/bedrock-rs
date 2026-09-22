use crate::error::EncryptionError;
use aes::Aes256;
use ctr::cipher::{StreamCipher, StreamCipherSeek};
use ctr::{Ctr128BE, cipher::KeyIvInit};
use p384::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct Encryption {
    encrypt_counter: u64,
    encrypt_cipher: Ctr128BE<Aes256>,
    decrypt_counter: u64,
    decrypt_cipher: Ctr128BE<Aes256>,
    key: [u8; 32],
}

/// [`Encryption`]'s state, for a cross-process handoff (see [`Encryption::export_state`]/
/// [`Encryption::import_state`]). The cipher objects themselves aren't serialized directly
/// (RustCrypto stream ciphers don't implement serde, and portably serializing raw cipher
/// internals across crate/version boundaries would be fragile) - AES-CTR's keystream is a
/// pure function of (key, IV, byte position), and the IV here is itself always a
/// deterministic function of `key` (see `Encryption::new`), so `key` plus each direction's
/// current keystream byte offset is sufficient to reconstruct an equivalent cipher at the
/// exact same position.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionState {
    key: [u8; 32],
    encrypt_counter: u64,
    encrypt_pos: u64,
    decrypt_counter: u64,
    decrypt_pos: u64,
}

fn iv_from_key(key: &[u8; 32]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..12].copy_from_slice(&key[..12]);
    iv[15] = 2;
    iv
}

impl Encryption {
    pub fn new(secret: &SecretKey, public: &PublicKey, token: &[u8; 16]) -> Self {
        let shared = secret.diffie_hellman(public);

        let shared_bytes = shared.raw_secret_bytes();

        let mut hasher = Sha256::new();
        hasher.update(token);
        hasher.update(shared_bytes);
        let key = hasher.finalize();
        let key: [u8; 32] = key.into();

        let iv = iv_from_key(&key);

        let encrypt_cipher = Ctr128BE::<Aes256>::new(&key.into(), (&iv).into());
        let decrypt_cipher = Ctr128BE::<Aes256>::new(&key.into(), (&iv).into());

        Self {
            encrypt_counter: 0,
            encrypt_cipher,
            decrypt_counter: 0,
            decrypt_cipher,
            key,
        }
    }

    /// Snapshot this session's encryption state for a cross-process handoff - see
    /// [`EncryptionState`] for why this is safe/correct (AES-CTR is inherently seekable,
    /// and nothing here is secret beyond what a process holding a live decrypted
    /// connection already has access to).
    pub fn export_state(&self) -> EncryptionState {
        EncryptionState {
            key: self.key,
            encrypt_counter: self.encrypt_counter,
            encrypt_pos: self.encrypt_cipher.current_pos(),
            decrypt_counter: self.decrypt_counter,
            decrypt_pos: self.decrypt_cipher.current_pos(),
        }
    }

    /// Reconstruct an `Encryption` continuing exactly where [`Encryption::export_state`]
    /// left off - same key, same per-direction keystream position, so the next
    /// `encrypt`/`decrypt` call produces bytes indistinguishable from the original
    /// session having continued uninterrupted.
    pub fn import_state(state: EncryptionState) -> Self {
        let iv = iv_from_key(&state.key);

        let mut encrypt_cipher = Ctr128BE::<Aes256>::new(&state.key.into(), (&iv).into());
        encrypt_cipher.seek(state.encrypt_pos);

        let mut decrypt_cipher = Ctr128BE::<Aes256>::new(&state.key.into(), (&iv).into());
        decrypt_cipher.seek(state.decrypt_pos);

        Self {
            encrypt_counter: state.encrypt_counter,
            encrypt_cipher,
            decrypt_counter: state.decrypt_counter,
            decrypt_cipher,
            key: state.key,
        }
    }

    pub fn encrypt(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, EncryptionError> {
        let trailer = self.trailer(&buf, self.encrypt_counter);

        let mut out = Vec::<u8>::with_capacity(buf.len() + trailer.len());
        out.extend_from_slice(&buf);
        out.extend_from_slice(&trailer);

        self.encrypt_cipher.apply_keystream(&mut out);

        self.encrypt_counter += 1;

        Ok(out)
    }

    pub fn decrypt(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, EncryptionError> {
        if buf.len() <= 8 {
            return Err(EncryptionError::InvalidLength(buf.len()));
        }

        let mut out = buf;
        self.decrypt_cipher.apply_keystream(&mut out);

        let trailer = &out[out.len() - 8..];
        let expected_trailer = self.trailer(&out[..out.len() - 8], self.decrypt_counter);
        if trailer != expected_trailer {
            return Err(EncryptionError::InvalidTrailer);
        }

        self.decrypt_counter += 1;

        out.truncate(out.len() - 8);
        Ok(out)
    }

    pub fn trailer(&self, buf: &[u8], counter: u64) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(counter.to_le_bytes());
        hasher.update(buf);
        hasher.update(self.key);
        let hash = hasher.finalize();

        let mut trailer = [0u8; 8];
        trailer.copy_from_slice(&hash[..8]);
        trailer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::SecretKey;

    /// Sets up a real matched pair the way an actual login handshake would - two
    /// independent EC keypairs, each side computing `Encryption::new` from its own
    /// secret and the other's public key. Fixed, deterministic scalars rather than
    /// an RNG - this is a unit test for the AES-CTR handoff logic, not for key
    /// generation, and it keeps the test independent of whichever RNG API the
    /// pinned elliptic-curve/rand versions happen to want this week.
    fn matched_pair() -> (Encryption, Encryption) {
        let token = [7u8; 16];
        let mut a_bytes = [0x11u8; 48];
        a_bytes[0] = 0x01; // avoid an all-identical-byte scalar landing on a degenerate point
        let mut b_bytes = [0x22u8; 48];
        b_bytes[0] = 0x02;

        let a_secret = SecretKey::from_slice(&a_bytes).expect("valid P-384 scalar");
        let b_secret = SecretKey::from_slice(&b_bytes).expect("valid P-384 scalar");

        let a = Encryption::new(&a_secret, &b_secret.public_key(), &token);
        let b = Encryption::new(&b_secret, &a_secret.public_key(), &token);
        (a, b)
    }

    /// The actual claim behind encryption export/import: encryption state
    /// exported from a live session and reconstructed in a second `Encryption`
    /// value keeps producing bytes the original peer can still decrypt - continuing
    /// the same AES-CTR keystream position, not restarting from zero.
    #[test]
    fn exported_state_resumes_the_same_keystream_position() {
        let (mut a, mut b) = matched_pair();

        // Exchange a few packets first so both sides' counters/keystream position
        // are already past their initial state, same as a session that's been
        // running for a while before a handoff.
        for i in 0..3 {
            let msg = format!("packet {i}").into_bytes();
            let ct = a.encrypt(msg.clone()).unwrap();
            assert_eq!(b.decrypt(ct).unwrap(), msg);
        }

        // Hand `a`'s encryption state off to a brand new instance - this is the
        // cross-process handoff step, just without an actual process boundary here.
        let state = a.export_state();
        let mut a_resumed = Encryption::import_state(state);

        // The original peer, `b`, was never told anything changed - it should still
        // be able to decrypt what the *resumed* instance encrypts, exactly as if
        // `a` itself had kept running uninterrupted.
        let msg = b"still the same session".to_vec();
        let ct = a_resumed.encrypt(msg.clone()).unwrap();
        assert_eq!(b.decrypt(ct).unwrap(), msg);

        // And it works both ways: `b` encrypting something new, `a_resumed`
        // decrypting it.
        let msg = b"reply after the handoff".to_vec();
        let ct = b.encrypt(msg.clone()).unwrap();
        assert_eq!(a_resumed.decrypt(ct).unwrap(), msg);
    }
}

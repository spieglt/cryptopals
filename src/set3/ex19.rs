/*

Break fixed-nonce CTR mode using substitutions

Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:

SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:

CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

And since the keystream is the same for every ciphertext:

CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
say!")

Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.
Don't overthink it.
Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.

*/

use crate::set3::ex18;
use crate::utils;
use rand::{Rng, thread_rng};

pub fn break_fixed_nonce_using_substitutions() {
	let nonce = [0; 8].to_vec();
	let mut _key = [0; 16];
	thread_rng().fill(&mut _key);
	let key = _key.to_vec();

	let plaintext_lines = utils::b64_file_to_byte_lines("./src/resources/19.txt");
	let encrypted_lines: Vec<Vec<u8>> = plaintext_lines.iter().map(|pt| {
		ex18::encrypt_ctr(
			&pt,
			&key,
			&nonce
		)
	}).collect();
	// println!("encrypted lines:");
	// encrypted_lines.iter().for_each(|l| println!("{:?}", l));

	// for each column, loop through all bytes, keep scores, append highest-score byte to keystream, use keystream to decrypt lines.
	// each run of loop represents one column of encrypted lines stacked on top of each other.
	let mut keystream = vec![];
	let mut i = 0;
	loop {
		let mut is_byte = false;
		let mut chars_to_be_scored = vec![];
		// for each character index of the encrypted lines
		for line in 0..encrypted_lines.len() {
			// see if len(current line) is > the byte we're on.
			// if so, add it to the temp list to be scored for letter frequency.
			// and record that we found a byte this loop through the list of strings
			// if not, pass.
			match encrypted_lines[line].len() > i {
				true => {
					is_byte = true;
					chars_to_be_scored.push(encrypted_lines[line][i]);
				},
				false => ()
			}
		}
		i += 1;
		if !is_byte { break; }

		// now we have a whole column and need to see which byte returns highest score.
		let mut best = (0u8, 0f64);
		for b in 0..=255 {
			let decrypted: Vec<u8> = chars_to_be_scored.iter().map(|c| c ^ b).collect();
			let score = utils::score_characters(&decrypted);
			if score > best.1 {
				best = (b, score);
			}
		}
		keystream.push(best.0);
	}

	let decrypted_lines: Vec<Vec<u8>> = encrypted_lines.iter().map(|el| {
		let mut res = vec![];
		for i in 0..el.len() {
			res.push(el[i] ^ keystream[i]);
		}
		res
	}).collect();
	decrypted_lines.iter().for_each(|l| utils::print_invalid_string(l));
}

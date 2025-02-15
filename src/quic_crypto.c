/*
  libdquic

  Copyright (C) 2024-2025 Vadim Vetrov <vetrovvd@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "dquic.h"
#include "kdf/hkdf.h"
#include "hash/sha256.h"
#include "cipher/aes.h"
#include "cipher_modes/ecb.h"
#include "aead/gcm.h"

const uint8_t quic_client_in_info[]	= "\0\x20\x0ftls13 client in\0";
const uint8_t quic_key_info[]		= "\0\x10\x0etls13 quic key\0";
const uint8_t quic_iv_info[]		= "\0\x0c\x0dtls13 quic iv\0";
const uint8_t quic_hp_info[]		= "\0\x10\x0dtls13 quic hp\0";
const uint8_t quic2_key_info[]		= "\0\x10\x10tls13 quicv2 key\0";
const uint8_t quic2_iv_info[]		= "\0\x0c\x0ftls13 quicv2 iv\0";
const uint8_t quic2_hp_info[]		= "\0\x10\x0ftls13 quicv2 hp\0";

const uint8_t quic_initial_salt[]	= "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
const uint8_t quic2_initial_salt[]	= "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9";

DQUIC_EXPORTED int quic_parse_initial_message(
	const uint8_t *quic_payload, size_t quic_plen,
	uint8_t **udecrypted_payload, size_t *udecrypted_payload_len
) {
	int ret;
	const struct quic_lhdr *qch;
	size_t qch_len;
	struct quic_cids qci;
	const uint8_t *inpayload; 
	size_t inplen;
	struct quici_hdr qich;

	size_t quic_header_len;
	size_t inheader_len;
	struct quici_lhdr_typespec qich_ltspc;
	int packet_number_length;
	const uint8_t *packet_number = NULL;
	const uint8_t *protected_payload = NULL;
	size_t protected_payload_length;

	uint8_t initial_secret[QUIC_INITIAL_SECRET_SIZE];
	uint8_t client_initial_secret[QUIC_CLIENT_IN_SIZE];
	uint8_t quic_key[QUIC_KEY_SIZE];
	uint8_t quic_iv[QUIC_IV_SIZE];
	uint8_t quic_hp[QUIC_HP_SIZE];
	uint8_t mask[QUIC_SAMPLE_SIZE];
	uint8_t *decrypted_payload = NULL;
	size_t decrypted_payload_len;
	uint8_t *decrypted_packet_number = NULL;
	uint8_t *dcptr = NULL;
	// Decrypted plain message without header
	uint8_t *decrypted_message = NULL;
	size_t decrypted_message_len;
	AesContext actx;
	GcmContext gctx;
	uint32_t qversion;
	const uint8_t *iv_info;
	size_t iv_info_size;
	const uint8_t *key_info;
	size_t key_info_size;
	const uint8_t *hp_info;
	size_t hp_info_size;
	const uint8_t *initial_salt;
	size_t initial_salt_size;

	ret = quic_parse_data(quic_payload, quic_plen,
			&qch, &qch_len, &qci, &inpayload, &inplen
	);
	if (ret < 0) {
		goto error_nfr;
	}

	ret = quic_get_version(&qversion, qch);
	if (ret < 0) {
		return -EINVAL;
	}
	if (!quic_check_is_initial(qch)) {
		return -EINVAL;
	}

	switch (qversion) {
		case QUIC_V1:
			iv_info = quic_iv_info;
			iv_info_size = sizeof(quic_iv_info) - 1;
			key_info = quic_key_info;
			key_info_size = sizeof(quic_key_info) - 1;
			hp_info = quic_hp_info;
			hp_info_size = sizeof(quic_hp_info) - 1;
			initial_salt = quic_initial_salt;
			initial_salt_size = sizeof(quic_initial_salt) - 1;
			break;
		case QUIC_V2:
			iv_info = quic2_iv_info;
			iv_info_size = sizeof(quic2_iv_info) - 1;
			key_info = quic2_key_info;
			key_info_size = sizeof(quic2_key_info) - 1;
			hp_info = quic2_hp_info;
			hp_info_size = sizeof(quic2_hp_info) - 1;
			initial_salt = quic2_initial_salt;
			initial_salt_size = sizeof(quic2_initial_salt) - 1;
			break;
		default:
			return -EINVAL;
	}

	quic_header_len = inpayload - quic_payload;

	ret = quic_parse_initial_header(inpayload, inplen, &qich);
	if (ret < 0) {
		goto error_nfr;
	}

	inheader_len = qich.protected_payload - inpayload;

	decrypted_payload_len = quic_header_len + inplen;
	decrypted_payload = malloc(decrypted_payload_len);
	if (decrypted_payload == NULL) {
		ret = -ENOMEM;
		goto error_nfr;
	}
	dcptr = decrypted_payload;
	// Copy quic large header
	memcpy(dcptr, quic_payload, quic_header_len);
	dcptr += quic_header_len;

	
	// Copy quic initial large header (until packet number)
	memcpy(dcptr, inpayload, inheader_len);
	dcptr += inheader_len;
	

	ret = hkdfExtract(SHA256_HASH_ALGO, (const unsigned char *)qci.dst_id, qci.dst_len, initial_salt, initial_salt_size, initial_secret);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	ret = hkdfExpand(SHA256_HASH_ALGO, initial_secret, SHA256_DIGEST_SIZE, quic_client_in_info, sizeof(quic_client_in_info) - 1, client_initial_secret, QUIC_CLIENT_IN_SIZE);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	ret = hkdfExpand(SHA256_HASH_ALGO, client_initial_secret, SHA256_DIGEST_SIZE, key_info, key_info_size, quic_key, QUIC_KEY_SIZE);	
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	ret = hkdfExpand(SHA256_HASH_ALGO, client_initial_secret, SHA256_DIGEST_SIZE, iv_info, iv_info_size, quic_iv, QUIC_IV_SIZE);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	ret = hkdfExpand(SHA256_HASH_ALGO, client_initial_secret, SHA256_DIGEST_SIZE, hp_info, hp_info_size, quic_hp, QUIC_HP_SIZE);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	// Decrypt packet number length and packet number
	ret = aesInit(&actx, quic_hp, QUIC_HP_SIZE);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}
	ret = ecbEncrypt(&aesCipherAlgo, &actx, 
		  qich.sample, mask, qich.sample_length);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	// Update decrypted payload header with decrypted packet_number_length
	decrypted_payload[0] ^= mask[0] & 0x0f;

	qich_ltspc = (struct quici_lhdr_typespec){decrypted_payload[0]};
	
	packet_number_length = qich_ltspc.number_length + 1;
	if (qich.length < packet_number_length) {
		ret = -EINVAL;
		goto error;
	}

	packet_number = qich.protected_payload;
	protected_payload = qich.protected_payload + packet_number_length;
	protected_payload_length = qich.length - packet_number_length;

	decrypted_packet_number = dcptr;

	for (int i = 0; i < packet_number_length; i++) {
		decrypted_packet_number[i] = packet_number[i] ^ mask[i + 1];
	}
	dcptr += packet_number_length;

	for (int i = QUIC_IV_SIZE - packet_number_length, j = 0; 
		i < QUIC_IV_SIZE; i++, j++) {

		quic_iv[i] ^= decrypted_packet_number[j];
	}
	
	ret = aesInit(&actx, quic_key, QUIC_KEY_SIZE);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}
	ret = gcmInit(&gctx, &aesCipherAlgo, &actx);
	if (ret) {
		ret = -EINVAL;
		goto error;
	}

	decrypted_message = dcptr;

	ret = gcmDecrypt(
		&gctx, quic_iv, QUIC_IV_SIZE, 
		NULL, 0, 
		protected_payload, decrypted_message, protected_payload_length, 
		quic_key, QUIC_KEY_SIZE
	);
	if (ret != 0 && ret != ERROR_FAILURE) {
		ret = -EINVAL;
		goto error;
	}

	if (!udecrypted_payload) {
		ret = -EINVAL;
		goto error;
	}

	*udecrypted_payload = decrypted_payload;
	if (udecrypted_payload_len) 
		*udecrypted_payload_len = decrypted_payload_len;
	
	return 0;
error:
	free(decrypted_payload);
error_nfr:
	return ret;
}

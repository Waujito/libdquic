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

#ifndef QUIC_H
#define QUIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

/**
* @macro
*
* :macro:`NGTCP2_INITIAL_SALT_V1` is a salt value which is used to
* derive initial secret.  It is used for QUIC v1.
*/
#define QUIC_INITIAL_SALT_V1 \
 "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad" \
 "\xcc\xbb\x7f\x0a"

/**
* @macro
*
* :macro:`NGTCP2_INITIAL_SALT_V2` is a salt value which is used to
* derive initial secret.  It is used for QUIC v2.
*/
#define QUIC_INITIAL_SALT_V2 \
 "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb" \
 "\xf9\xbd\x2e\xd9"

#define QUIC_INITIAL_TYPE	0
#define QUIC_0_RTT_TYPE		1
#define QUIC_HANDSHAKE_TYPE	2
#define QUIC_RETRY_TYPE		3

#define QUIC_INITIAL_TYPE_V1	0b00
#define QUIC_0_RTT_TYPE_V1	0b01
#define QUIC_HANDSHAKE_TYPE_V1	0b10
#define QUIC_RETRY_TYPE_V1	0b11
#define quic_convtype_v1(type) (type)

#define QUIC_INITIAL_TYPE_V2	0b01
#define QUIC_0_RTT_TYPE_V2	0b10
#define QUIC_HANDSHAKE_TYPE_V2	0b11
#define QUIC_RETRY_TYPE_V2	0b00
#define quic_convtype_v2(type) (((type) + 1) & __extension__ 0b11)

#define QUIC_FRAME_CRYPTO	0x06
#define QUIC_FRAME_PADDING	0x00
#define QUIC_FRAME_PING		0x01

#define QUIC_V1	1		// RFC 9000
#define QUIC_V2	0x6b3343cf	// RFC 9369

static const uint32_t supported_versions[] = {
	QUIC_V1,
	QUIC_V2,
};

// In bytes
#define QUIC_SAMPLE_OFFSET		4

#define QUIC_SAMPLE_SIZE		16
#define QUIC_INITIAL_SECRET_SIZE	32
#define QUIC_CLIENT_IN_SIZE		32
#define QUIC_KEY_SIZE			16
#define QUIC_IV_SIZE			12
#define QUIC_HP_SIZE			16
// Altough tag is not defined, it present in the end of message
#define QUIC_TAG_SIZE			16


/**
 * Describes type-specific bytes for Initial message
 */
struct quici_lhdr_typespec {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t number_length:2;//protected
	uint8_t reserved:2;	//protected
	uint8_t discard:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t discard:4;
	uint8_t reserved:2;	//protected
	uint8_t number_length:2;//protected
#else
#error "Undefined endian"
#endif
}__attribute__((packed));

/**
 * Quic Large Header
 */
struct quic_lhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t type_specific:4;// protected
	uint8_t type:2;
	uint8_t fixed:1;
	uint8_t form:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t form:1;
	uint8_t fixed:1;
	uint8_t type:2;
	uint8_t type_specific:4;// protected
#else
#error "Undefined endian"
#endif
	uint32_t version;
}__attribute__((packed));

/**
 * Quic Large Header Ids 
 * (separated from the original header because of varying dst 
 */
struct quic_cids {
	uint8_t dst_len;
	const uint8_t *dst_id;
	uint8_t src_len;
	const uint8_t *src_id;
};

/**
 * Parses QUIС raw data (UDP payload) to quic large header and 
 * quic payload.
 *
 * \qch_len is sizeof(qch) + qci->dst_len + qci->src_id
 * \payload is Type-Specific payload (#17.2).
 */
int quic_parse_data(const uint8_t *raw_payload, size_t raw_payload_len,
		const struct quic_lhdr **qch, size_t *qch_len,
		struct quic_cids *qci,
		const uint8_t **payload, size_t *plen);
		

/**
 * Parses QUIC variable-length integer. (#16)
 * \variable is a pointer to the sequence to be parsed
 * (varlen integer in big endian format)
 *
 * \mlen Used to signal about variable length and validate left length
 * in the buffer.
 *
 * On error/buffer overflow mlen set to 0, otherwise it is higher
 */
uint64_t quic_parse_varlength(const uint8_t *variable, size_t *mlen);

// quici stands for QUIC Initial

/**
 * This structure should be parsed. 
 * Represents ENCRYPTED Initial header
 */
struct quici_hdr {
	size_t token_len;
	const uint8_t *token;
	size_t length;

	const uint8_t *protected_payload; //  with packet number

	// RFC 9001 5.4.2
	size_t sample_length;
	const uint8_t *sample;
};

struct quici_decrypted_hdr {
	size_t token_len;
	const uint8_t *token;
	size_t length;

	uint32_t packet_number;

	const uint8_t *decrypted_message;
	size_t decrypted_message_len;
};

/**
 * Checks for quic version and checks if it is supported
 */
int quic_get_version(uint32_t *version, const struct quic_lhdr *qch);

/**
* Checks quic message to be initial according to version. 
* 0 on false, 1 on true
*/
int quic_check_is_initial(const struct quic_lhdr *qch);

struct quic_frame_crypto {
	size_t offset;
	size_t payload_length;
	const uint8_t *payload;
};
/**
 * Parses quic crypto frame
 * Returns parsed size or -EINVAL on error
 */
int quic_parse_crypto(struct quic_frame_crypto *crypto_frame,
			  const uint8_t *frame, size_t flen);


/**
 * Parses QUIC initial message header.
 * \inpayload is a QUIC Initial message payload (payload after quic large header)
 */
int quic_parse_initial_header(const uint8_t *inpayload, size_t inplen,
			struct quici_hdr *qhdr);

/**
 * Parses decrypted QUIC initial message header.
 * \quic_payload is udecrypted_payload (decrypted quic packet) 
 */
int quic_parse_decrypted_initial_header(const uint8_t *quic_payload, 
					size_t quic_plen,
			struct quici_decrypted_hdr *qhdr);

/**
 * Parses and decrypts QUIC Initial Message. 
 *
 * \quic_header QUIC payload, the start of UDP payload
 * \udecrypted_payload QUIC decrypted payload. Contains all the QUIC packet, with all headers
 *
 * udecrypted_payload MUST be freed.
 *
 */
int quic_parse_initial_message(
	const uint8_t *quic_payload, size_t quic_plen,
	uint8_t **udecrypted_payload, size_t *udecrypted_payload_len
);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_H */

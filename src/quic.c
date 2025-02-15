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

#include "quic.h"

#include <errno.h>
#include <stdio.h>

#if defined(_WIN32)
	#include <winsocks2.h>
#else
	#include <arpa/inet.h>
#endif


/**
 * Packet number.
 */
struct quic_pnumber {
	uint8_t d1;
	uint8_t d2;
	uint8_t d3;
	uint8_t d4;
};

uint64_t quic_parse_varlength(const uint8_t *variable, size_t *mlen) {
	if (mlen && *mlen == 0) return 0;
	uint64_t vr = (*variable & 0x3F);
	uint8_t len = 1 << (*variable >> 6);

	if (mlen) {
		if (*mlen < len) {
			*mlen = 0;
			return 0;
		}
		*mlen = len;
	}

	++variable;
	for (uint8_t i = 1; i < len; i++) {
		vr = (vr << 8) + *variable;
		++variable;
	}

	return vr;
}

int quic_get_version(uint32_t *version, const struct quic_lhdr *qch) {
	uint32_t qversion = ntohl(qch->version);
	*version = qversion;

	switch (qversion) {
		case QUIC_V1:
		case QUIC_V2:
			return 0;
		default:
			return -EINVAL;
	}
}

int quic_check_is_initial(const struct quic_lhdr *qch) {
	uint32_t qversion;
	int ret;
	ret = quic_get_version(&qversion, qch);
	if (ret < 0) return 0;

	uint8_t qtype = qch->type;

	switch (qversion) {
		case QUIC_V1:
			qtype = quic_convtype_v1(qtype);
			break;
		case QUIC_V2:
			qtype = quic_convtype_v2(qtype);
			break;
		default:
			return 0;
	}

	if (qtype != QUIC_INITIAL_TYPE) {
		return 0;
	}

	return 1;
}

int quic_parse_data(const uint8_t *raw_payload, size_t raw_payload_len,
		const struct quic_lhdr **qch, size_t *qch_len,
		struct quic_cids *qci,
		const uint8_t **payload, size_t *plen) {
	if (	raw_payload == NULL || 
		raw_payload_len < sizeof(struct quic_lhdr)) 
		goto invalid_packet;

	const struct quic_lhdr *nqch = (const struct quic_lhdr *)raw_payload;
	size_t left_len = raw_payload_len - sizeof(struct quic_lhdr);
	const uint8_t *cur_rawptr = raw_payload + sizeof(struct quic_lhdr);
	int ret;
	uint32_t qversion;

	if (!nqch->fixed) {
		return -EPROTO;
	}

	ret = quic_get_version(&qversion, nqch);

	if (ret < 0) {
		return -EPROTO;
	}

	if (left_len < 2) goto invalid_packet;
	struct quic_cids nqci = {0};

	nqci.dst_len = *cur_rawptr++;
	left_len--;
	if (left_len < nqci.dst_len) goto invalid_packet;
	nqci.dst_id = cur_rawptr;
	cur_rawptr += nqci.dst_len;
	left_len -= nqci.dst_len;

	nqci.src_len = *cur_rawptr++;
	left_len--;
	if (left_len < nqci.src_len) goto invalid_packet;
	nqci.src_id = cur_rawptr;
	cur_rawptr += nqci.src_len;
	left_len -= nqci.src_len;

	if (qch) *qch = nqch;
	if (qch_len) {
		*qch_len = sizeof(struct quic_lhdr) + 
			nqci.src_len + nqci.dst_len;
	}
	if (qci) *qci = nqci;
	if (payload) *payload = cur_rawptr;
	if (plen) *plen = left_len;

	return 0;

invalid_packet:
	return -EINVAL;
}

int quic_parse_initial_header(const uint8_t *inpayload, size_t inplen,
			struct quici_hdr *qhdr) {
	if (inplen < 3) goto invalid_packet;
	struct quici_hdr nqhdr;

	const uint8_t *cur_ptr = inpayload;
	size_t left_len = inplen;
	size_t tlen = left_len;

	nqhdr.token_len = quic_parse_varlength(cur_ptr, &tlen);
	nqhdr.token = cur_ptr + tlen;
	
	if (left_len < nqhdr.token_len + tlen) 
		goto invalid_packet;
	cur_ptr += tlen + nqhdr.token_len;
	left_len -= tlen + nqhdr.token_len;

	tlen = left_len;
	nqhdr.length = quic_parse_varlength(cur_ptr, &tlen);

	if (left_len < nqhdr.length + tlen ||
		nqhdr.length < QUIC_SAMPLE_SIZE + 
				QUIC_SAMPLE_OFFSET
	)
		goto invalid_packet;
	cur_ptr += tlen;

	nqhdr.protected_payload = cur_ptr;
	nqhdr.sample = cur_ptr + QUIC_SAMPLE_OFFSET;
	nqhdr.sample_length = QUIC_SAMPLE_SIZE;

	if (qhdr) *qhdr = nqhdr;

	return 0;

invalid_packet:
	return -EINVAL;
}

int quic_parse_decrypted_initial_header(const uint8_t *quic_payload, 
					size_t quic_plen,
			struct quici_decrypted_hdr *qhdr) {
	const uint8_t *inpayload;
	size_t inplen;
	const struct quic_lhdr *qch;
	struct quici_lhdr_typespec quici_lhdr;

	const uint8_t *raw_packet_number;
	int packet_number_length;
	uint32_t packet_number;
	int ret;

	ret = quic_parse_data(
		quic_payload, quic_plen,
		&qch, NULL, NULL,
		&inpayload, &inplen);

	if (ret < 0) {
		goto invalid_packet;
	}
	quici_lhdr = (struct quici_lhdr_typespec){quic_payload[0]};

	if (inplen < 3) goto invalid_packet;
	struct quici_decrypted_hdr nqhdr = {0};

	const uint8_t *cur_ptr = inpayload;
	size_t left_len = inplen;
	size_t tlen = left_len;

	nqhdr.token_len = quic_parse_varlength(cur_ptr, &tlen);
	nqhdr.token = cur_ptr + tlen;
	
	if (left_len < nqhdr.token_len + tlen) {
		goto invalid_packet;
	}
	cur_ptr += tlen + nqhdr.token_len;
	left_len -= tlen + nqhdr.token_len;

	tlen = left_len;
	nqhdr.length = quic_parse_varlength(cur_ptr, &tlen);

	if (left_len < nqhdr.length + tlen ||
		nqhdr.length < QUIC_SAMPLE_SIZE + 
				QUIC_SAMPLE_OFFSET
	) {
		goto invalid_packet;
	}
	cur_ptr += tlen;

	packet_number_length = quici_lhdr.number_length + 1;
	raw_packet_number = cur_ptr;

	packet_number = 0;
	for (int i = 0; i < packet_number_length; i++) {
		packet_number = (packet_number << 8) + raw_packet_number[i];
	}
	nqhdr.packet_number = packet_number;

	cur_ptr += packet_number_length;

	nqhdr.decrypted_message = cur_ptr;
	nqhdr.decrypted_message_len = nqhdr.length - packet_number_length - QUIC_TAG_SIZE;

	if (qhdr) *qhdr = nqhdr;

	return 0;

invalid_packet:
	return -EINVAL;
}

int quic_parse_crypto(struct quic_frame_crypto *crypto_frame,
			  const uint8_t *frame, size_t flen) {
	const uint8_t *curptr = frame;
	size_t curptr_len = flen;
	size_t vln;
	*crypto_frame = (struct quic_frame_crypto){0};

	if (flen == 0 || *frame != QUIC_FRAME_CRYPTO || 
		crypto_frame == NULL) 
		return -EINVAL;

	
	curptr++, curptr_len--;

	vln = curptr_len;
	size_t offset = quic_parse_varlength(curptr, &vln);
	curptr += vln, curptr_len -= vln;
	if (vln == 0) {
		return -EINVAL;
	}
	

	vln = curptr_len;
	size_t length = quic_parse_varlength(curptr, &vln);
	curptr += vln, curptr_len -= vln;
	if (vln == 0) {
		return -EINVAL;
	}

	if (length > curptr_len)
		return -EINVAL;

	crypto_frame->offset = offset;
	crypto_frame->payload_length = length;
	crypto_frame->payload = curptr;

	curptr += length;
	curptr_len -= length;

	return flen - curptr_len;
}


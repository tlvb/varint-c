#include "varint.h"

int varint_classify_v(uint8_t b0) { /*{{{*/
	if ((b0 & 0xfc) == VARINT_NEG_R)       { return VARINT_NEG_R; }
	else if ((b0 & 0xfc) == VARINT_NEG_2)  { return VARINT_NEG_2; }
	else if ((b0 & 0x80) == VARINT_POS_7)  { return VARINT_POS_7; }
	else if ((b0 & 0xc0) == VARINT_POS_14) { return VARINT_POS_14; }
	else if ((b0 & 0xe0) == VARINT_POS_21) { return VARINT_POS_21; }
	else if ((b0 & 0xf0) == VARINT_POS_28) { return VARINT_POS_28; }
	else if ((b0 & 0xfc) == VARINT_POS_32) { return VARINT_POS_32; }
	else if ((b0 & 0xfc) == VARINT_POS_64) { return VARINT_POS_64; }
	return VARINT_INVALID;
} /*}}}*/
int varint_classify_i(int64_t i) { /*{{{*/
	if (i < -3)       { return VARINT_NEG_R; }
	else if (i < 0)   { return VARINT_NEG_2; }
	else if ((i & ~0x000000000000007f) == 0) { return VARINT_POS_7;  }
	else if ((i & ~0x0000000000003fff) == 0) { return VARINT_POS_14; }
	else if ((i & ~0x00000000001fffff) == 0) { return VARINT_POS_21; }
	else if ((i & ~0x000000000fffffff) == 0) { return VARINT_POS_28; }
	else if ((i & ~0x0000000fffffffff) == 0) { return VARINT_POS_32; }
	return VARINT_POS_64;
} /*}}}*/
size_t varint_len_i(int64_t i) { /*{{{*/
	switch (varint_classify_i(i)) {
		case VARINT_NEG_R:  return 1+varint_len_i(-i);
		case VARINT_NEG_2:
		case VARINT_POS_7:  return 1;
		case VARINT_POS_14: return 2;
		case VARINT_POS_21: return 3;
		case VARINT_POS_28: return 4;
		case VARINT_POS_32: return 5;
		case VARINT_POS_64: return 9;
		default: return 0;
	}
} /*}}}*/
bool varint_identify(int *type, int *rtype, size_t *len, const uint8_t *buf, size_t lim) { /*{{{*/
	// It is technically possible to construct a varint that has more than one
	// negative recursive marker, but this code treats it as an error.
	if (type == NULL) { return false; }
	*type = VARINT_INVALID;
	*len = 0;
	if (lim < 1) { return false; }
	*type = varint_classify_v(buf[0]);
	switch (*type) {
		case VARINT_NEG_R:
			if (!varint_identify(rtype, NULL, len, buf+1, lim-1)) {
				*type = VARINT_INVALID;
				*len = 0;
				return false;
			}
			*len += 1;
			break;
		case VARINT_NEG_2:
		case VARINT_POS_7:
			*len = 1;
			break;
		case VARINT_POS_14:
			*len = 2;
			break;
		case VARINT_POS_21:
			*len = 3;
			break;
		case VARINT_POS_28:
			*len = 4;
			break;
		case VARINT_POS_32:
			*len = 5;
			break;
		case VARINT_POS_64:
			*len = 9;
			break;
		default:
			*len = 0;
			return false;
	}
	return true;
} /*}}}*/
int64_t varint_decode_(int type, const uint8_t *buf) { /*{{{*/
	/* A buffer read limit is not supplied since the function
	 * is only for internal use in cases where the limit has
	 * already been checked and determined to be of sufficient
	 * length.
	 */
	switch (type) {
		case VARINT_NEG_2:
			return (uint64_t)(buf[0]&0x03);
		case VARINT_POS_7:
			return buf[0];
		case VARINT_POS_14:
			return (((uint64_t)(buf[0]&0x3f))<<8) | buf[1];
		case VARINT_POS_21:
			return (((uint64_t)(buf[0]&0x1f))<<16) | (((uint64_t)buf[1])<<8) | ((uint64_t)buf[2]);
		case VARINT_POS_28:
			return (((uint64_t)(buf[0]&0x0f))<<24) | (((uint64_t)buf[1])<<16) | (((uint64_t)buf[2])<<8) | ((uint64_t)buf[3]);
		case VARINT_POS_32:
			return (((uint64_t)buf[1])<<24) | (((uint64_t)buf[2])<<16) | (((uint64_t)buf[3])<<8) | ((uint64_t)buf[4]);
		case VARINT_POS_64:
			return (((uint64_t)buf[1])<<56) | (((uint64_t)buf[2])<<48) | (((uint64_t)buf[3])<<40) | (((uint64_t)buf[4])<<32) | (((uint64_t)buf[5])<<24) | (((uint64_t)buf[6])<<16) | (((uint64_t)buf[7])<<8) | ((uint64_t)buf[8]);
		default:
			return 0;
	}
} /*}}}*/
size_t varint_decode(int64_t *i, const uint8_t *buf, size_t lim) { /*{{{*/
	int type = VARINT_INVALID;
	int rtype = VARINT_INVALID;
	size_t len;
	if (varint_identify(&type, &rtype, &len, buf, lim)) {
		switch (type) {
			case VARINT_NEG_R:
				*i = -varint_decode_(rtype, buf+1);
				break;
			default:
				*i = varint_decode_(type, buf);
				break;
		}
		return len;
	}
	*i = 0;
	return 0;
} /*}}}*/
size_t varint_encode(uint8_t *buf, size_t lim, int64_t i) { /*{{{*/
	int type = varint_classify_i(i);
	if (lim < 1) { return 0; }
	switch (type) {
		case VARINT_NEG_R:
			if (lim < 2) { break; }
			buf[0] = VARINT_NEG_R;
			size_t n = varint_encode(buf+1, lim-1, -i);
			if (n != 0) { return n; }
			break;
		case VARINT_NEG_2:
			buf[0] = VARINT_NEG_2 | (0x03 & (-i));
			return 1;
		case VARINT_POS_7:
			buf[0] = VARINT_POS_7 | (0x7f & i);
			return 1;
		case VARINT_POS_14:
			if (lim < 2) { break; }
			buf[0] = VARINT_POS_14 | (0x3f & (i>>8));
			buf[1] = 0xff & i;
			return 2;
		case VARINT_POS_21:
			if (lim < 3) { break; }
			buf[0] = VARINT_POS_21 | (0x1f & (i>>16));
			buf[1] = 0xff & (i>>8);
			buf[2] = 0xff & (i   );
			return 3;
		case VARINT_POS_28:
			if (lim < 4) { break; }
			buf[0] = VARINT_POS_28 | (0x0f & (i>>24));
			buf[1] = 0xff & (i>>16);
			buf[2] = 0xff & (i>> 8);
			buf[3] = 0xff & (i    );
			return 4;
		case VARINT_POS_32:
			if (lim < 5) { break; }
			buf[0] = VARINT_POS_32;
			buf[1] = 0xff & (i>>24);
			buf[2] = 0xff & (i>>16);
			buf[3] = 0xff & (i>> 8);
			buf[4] = 0xff & (i    );
			return 5;
		case VARINT_POS_64:
			if (lim < 9) { break; }
			buf[0] = VARINT_POS_64;
			buf[1] = 0xff & (i>>56);
			buf[2] = 0xff & (i>>48);
			buf[3] = 0xff & (i>>40);
			buf[4] = 0xff & (i>>32);
			buf[5] = 0xff & (i>>24);
			buf[6] = 0xff & (i>>16);
			buf[7] = 0xff & (i>> 8);
			buf[8] = 0xff & (i    );
			return 9;
		default:
			break;
	}
	return 0;
} /*}}}*/

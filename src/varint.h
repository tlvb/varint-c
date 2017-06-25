#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#define VARINT_NEG_R   0xf8
#define VARINT_NEG_2   0xfc
#define VARINT_POS_7   0x00
#define VARINT_POS_14  0x80
#define VARINT_POS_21  0xc0
#define VARINT_POS_28  0xe0
#define VARINT_POS_32  0xf0
#define VARINT_POS_64  0xf4
#define VARINT_INVALID 0xff

int varint_classify_v(uint8_t buf0);
int varint_classify_i(int64_t i);
size_t varint_len_i(int64_t i);
bool varint_identify(int *type, int *rtype, size_t *len, const uint8_t *buf, size_t lim);
size_t varint_decode(int64_t *i, const uint8_t *buf, size_t lim);
size_t varint_encode(uint8_t *buf, size_t lim, int64_t i);

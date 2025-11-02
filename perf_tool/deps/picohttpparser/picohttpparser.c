/*
 * Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
 *                         Shigeo Fushimi
 * 
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <assert.h> 
#include <stddef.h> 
#include <string.h> 
#ifdef __SSE4_2__ 
#ifdef _MSC_VER 
#include <nmmintrin.h> 
#else 
#include <x86intrin.h> 
#endif 
#endif 
#include "picohttpparser.h"
#include <stdbool.h>

#if __GNUC__ >= 3 
#define likely(x) __builtin_expect(!!(x), 1) 
#define unlikely(x) __builtin_expect(!!(x), 0) 
#else 
#define likely(x) (x) 
#define unlikely(x) (x) 
#endif

#ifdef _MSC_VER 
#define ALIGNED(n) _declspec(align(n)) 
#else 
#define ALIGNED(n) __attribute__((aligned(n))) 
#endif

#define IS_PRINTABLE_ASCII(c) ((unsigned char)(c)-040u < 0137u)

#define CHECK_EOF()                                                                                                                \
    if (buf == buf_end) {                                                                                                          \
        *ret = -2;                                                                                                                 \
        return NULL;                                                                                                               \
    }

#define EXPECT_CHAR_NO_CHECK(ch)                                                                                                   \
    if (*buf++ != ch) {                                                                                                            \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }

#define EXPECT_CHAR(ch)                                                                                                            \
    CHECK_EOF();                                                                                                                   \
    EXPECT_CHAR_NO_CHECK(ch);

#define ADVANCE_TOKEN(tok, tok_len)                                                                                                \
    do {                                                                                                                           \
        const char *tok_start = buf;                                                                                               \
        CHECK_EOF();                                                                                                               \
        while (1) {                                                                                                                \
            if (*buf == ' ') {                                                                                                     \
                break;                                                                                                             \
            } else if (unlikely(!IS_PRINTABLE_ASCII(*buf))) {                                                                       \
                if ((unsigned char)*buf < 040 || *buf == 0177) {                                                                    \
                    *ret = -1;                                                                                                     \
                    return NULL;                                                                                                   \
                }                                                                                                                  \
            }                                                                                                                      \
            ++buf;                                                                                                                 \
            CHECK_EOF();                                                                                                               \
        }                                                                                                                          \
        tok = tok_start;                                                                                                           \
        tok_len = buf - tok_start;                                                                                                 \
    } while (0)

static const char *token_char_map = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                  "\0\1\0\1\1\1\1\1\0\0\1\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0"
                                  "\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\1\1"
                                  "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\0\0\0"
                                  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static const char *find_ch_fast(const char *buf, const char *buf_end, char ch) {
    while (1) {
        if (buf == buf_end)
            return NULL;
        if (*buf == ch)
            return buf;
        ++buf;
    }
}

static const char *get_token_to_ch(const char *buf, const char *buf_end, const char **token, size_t *token_len, char ch,
                                   int *ret) {
    const char *token_start = buf;

    buf = find_ch_fast(buf, buf_end, ch);
    if (buf == NULL) {
        CHECK_EOF();
        return NULL; /* should not be reached */
    }

    while (1) {
        if (*(buf - 1) != ' ') {
            break;
        }
        --buf;
        if (buf == token_start) {
            *ret = -1;
            return NULL;
        }
    }

    *token = token_start;
    *token_len = buf - token_start;

    return buf;
}

static const char *parse_http_version(const char *buf, const char *buf_end, int *minor_version, int *ret) {
    /* we want "HTTP/1.x" */
    EXPECT_CHAR('H');
    EXPECT_CHAR('T');
    EXPECT_CHAR('T');
    EXPECT_CHAR('P');
    EXPECT_CHAR('/');
    EXPECT_CHAR('1');
    EXPECT_CHAR('.');
    CHECK_EOF();
    if (!('0' <= *buf && *buf <= '9')) {
        *ret = -1;
        return NULL;
    }
    *minor_version = *buf++ - '0';
    return buf;
}

static const char *parse_headers(const char *buf, const char *buf_end, struct phr_header *headers, size_t *num_headers,
                                 size_t max_headers, int *ret) {
    for (;; ++*num_headers) {
        CHECK_EOF();
        if (*buf == '\r') {
            ++buf;
            EXPECT_CHAR('\n');
            break;
        }
        if (*buf == '\n') {
            ++buf;
            break;
        }
        if (*num_headers == max_headers) {
            *ret = -1;
            return NULL;
        }
        if (!(*num_headers != 0 && (*buf == ' ' || *buf == '\t'))) {
            /* parsing name, but do not discard SP before name, since some clients might send "\r\n"+SP before the name of the next
             * header */
            headers[*num_headers].name = buf;
            const char *colon = find_ch_fast(buf, buf_end, ':');
            if (colon == NULL) {
                CHECK_EOF();
                return NULL; /* should not be reached */
            }
            headers[*num_headers].name_len = colon - buf;
            buf = colon;
        } else {
            headers[*num_headers].name = NULL;
            headers[*num_headers].name_len = 0;
        }
        ++buf; /* skip ":" */
        while (1) {
            CHECK_EOF();
            if (!(*buf == ' ' || *buf == '\t')) {
                break;
            }
            ++buf;
        }
        headers[*num_headers].value = buf;
        const char *cr = find_ch_fast(buf, buf_end, '\r');
        const char *lf = find_ch_fast(buf, buf_end, '\n');
        if (cr != NULL && (lf == NULL || cr < lf)) {
            headers[*num_headers].value_len = cr - buf;
            buf = cr + 1;
            EXPECT_CHAR_NO_CHECK('\n');
        } else if (lf != NULL) {
            headers[*num_headers].value_len = lf - buf;
            buf = lf + 1;
        } else {
            CHECK_EOF();
            return NULL; /* should not be reached */
        }
    }
    return buf;
}

static const char *parse_request(const char *buf, const char *buf_end, const char **method, size_t *method_len, const char **path,
                                 size_t *path_len, int *minor_version, struct phr_header *headers, size_t *num_headers,
                                 size_t max_headers, int *ret) {
    /* skip first empty line (some clients add CRLF after POST) */
    CHECK_EOF();
    if (*buf == '\r') {
        ++buf;
        EXPECT_CHAR('\n');
    } else if (*buf == '\n') {
        ++buf;
    }

    /* parse request line */
    ADVANCE_TOKEN(*method, *method_len);
    ++buf;
    ADVANCE_TOKEN(*path, *path_len);
    ++buf;
    if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
        return NULL;
    }
    if (*buf == '\r') {
        ++buf;
        EXPECT_CHAR('\n');
    } else if (*buf == '\n') {
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }

    return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

int phr_parse_request(const char *buf_start, size_t len, const char **method, size_t *method_len, const char **path,
                      size_t *path_len, int *minor_version, struct phr_header *headers, size_t *num_headers, size_t last_len) {
    const char *buf = buf_start, *buf_end = buf_start + len;
    size_t max_headers = *num_headers;
    int ret = 0;

    *method = NULL;
    *method_len = 0;
    *path = NULL;
    *path_len = 0;
    *minor_version = -1;
    *num_headers = 0;

    /* if last_len != 0, continue where we left off */
    if (last_len != 0) {
        buf = buf + last_len;
    }

    if ((buf = parse_request(buf, buf_end, method, method_len, path, path_len, minor_version, headers, num_headers, max_headers,
                             &ret)) == NULL) {
        return ret;
    }

    return (int)(buf - buf_start);
}

static const char *parse_response(const char *buf, const char *buf_end, int *minor_version, int *status, const char **msg,
                                  size_t *msg_len, struct phr_header *headers, size_t *num_headers, size_t max_headers,
                                  int *ret) {
    /* parse "HTTP/1.x" */
    if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
        return NULL;
    }
    /* skip space */
    if (*buf++ != ' ') {
        *ret = -1;
        return NULL;
    }
    /* parse status code, which is a 3-digit number */
    CHECK_EOF();
    if (!('1' <= *buf && *buf <= '9')) {
        *ret = -1;
        return NULL;
    }
    *status = 0;
    for (int i = 0; i < 3; ++i) {
        CHECK_EOF();
        if (!('0' <= *buf && *buf <= '9')) {
            *ret = -1;
            return NULL;
        }
        *status = *status * 10 + *buf++ - '0';
    }
    /* skip space */
    if (*buf++ != ' ') {
        *ret = -1;
        return NULL;
    }
    /* get message */
    if ((buf = get_token_to_ch(buf, buf_end, msg, msg_len, '\r', ret)) == NULL) {
        return NULL;
    }
    if (*buf++ != '\r') {
        *ret = -1;
        return NULL;
    }
    if (*buf++ != '\n') {
        *ret = -1;
        return NULL;
    }

    return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

int phr_parse_response(const char *buf_start, size_t len, int *minor_version, int *status, const char **msg, size_t *msg_len,
                       struct phr_header *headers, size_t *num_headers, size_t last_len) {
    const char *buf = buf_start, *buf_end = buf_start + len;
    size_t max_headers = *num_headers;
    int ret = 0;

    *minor_version = -1;
    *status = 0;
    *msg = NULL;
    *msg_len = 0;
    *num_headers = 0;

    /* if last_len != 0, continue where we left off */
    if (last_len != 0) {
        buf = buf + last_len;
    }

    if ((buf = parse_response(buf, buf_end, minor_version, status, msg, msg_len, headers, num_headers, max_headers, &ret)) ==
        NULL) {
        return ret;
    }

    return (int)(buf - buf_start);
}

int phr_parse_headers(const char *buf_start, size_t len, struct phr_header *headers, size_t *num_headers, size_t last_len) {
    const char *buf = buf_start, *buf_end = buf_start + len;
    size_t max_headers = *num_headers;
    int ret = 0;

    *num_headers = 0;

    /* if last_len != 0, continue where we left off */
    if (last_len != 0) {
        buf = buf + last_len;
    }

    if ((buf = parse_headers(buf, buf_end, headers, num_headers, max_headers, &ret)) == NULL) {
        return ret;
    }

    return (int)(buf - buf_start);
}

enum {
    CHUNKED_IN_CHUNK_SIZE,
    CHUNKED_IN_CHUNK_EXT,
    CHUNKED_IN_CHUNK_DATA,
    CHUNKED_IN_CHUNK_CRLF,
    CHUNKED_IN_TRAILERS_LINE_HEAD,
    CHUNKED_IN_TRAILERS_LINE_MIDDLE
};

static int phr_decode_hex(int ch) {
    if ('0' <= ch && ch <= '9') {
        return ch - '0';
    } else if ('A' <= ch && ch <= 'F') {
        return ch - 'A' + 10;
    } else if ('a' <= ch && ch <= 'f') {
        return ch - 'a' + 10;
    } else {
        return -1;
    }
}

ssize_t phr_decode_chunked(struct phr_chunked_decoder *decoder, char *buf, size_t *_bufsz) {
    size_t bufsz = *_bufsz;
    const char *buf_start = buf;
    const char *buf_end = buf + bufsz;
    ssize_t ret = -2; /* incomplete */

    while (1) {
        switch (decoder->_state) {
        case CHUNKED_IN_CHUNK_SIZE:
            for (;; ++buf) {
                int v;
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if ((v = phr_decode_hex(*buf)) == -1) {
                    if (*buf == ';' || *buf == ' ') {
                        decoder->_state = CHUNKED_IN_CHUNK_EXT;
                        break;
                    }
                    goto L_error;
                }
                if (decoder->_hex_count == sizeof(size_t) * 2) {
                    goto L_error;
                }
                decoder->bytes_left_in_chunk = decoder->bytes_left_in_chunk * 16 + v;
                decoder->_hex_count++;
            }
            break;
        case CHUNKED_IN_CHUNK_EXT:
            /* skip until CRLF */
            for (;; ++buf) {
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if (*buf == '\n') {
                    break;
                }
            }
            ++buf;
            decoder->_state = CHUNKED_IN_CHUNK_SIZE;
            if (decoder->bytes_left_in_chunk == 0) {
                if (decoder->consume_trailer) {
                    decoder->_state = CHUNKED_IN_TRAILERS_LINE_HEAD;
                } else {
                    ret = -1; /* final chunk received */
                }
            } else {
                decoder->_state = CHUNKED_IN_CHUNK_DATA;
            }
            break;
        case CHUNKED_IN_CHUNK_DATA:
            if (buf_end - buf >= (ssize_t)decoder->bytes_left_in_chunk) {
                buf += decoder->bytes_left_in_chunk;
                decoder->bytes_left_in_chunk = 0;
                decoder->_state = CHUNKED_IN_CHUNK_CRLF;
            } else {
                decoder->bytes_left_in_chunk -= buf_end - buf;
                buf = (char *)buf_end;
                goto L_incomplete;
            }
            break;
        case CHUNKED_IN_CHUNK_CRLF:
            for (;; ++buf) {
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if (*buf != '\r') {
                    break;
                }
                ++buf;
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if (*buf != '\n') {
                    break;
                }
                ++buf;
                decoder->_state = CHUNKED_IN_CHUNK_SIZE;
                goto L_again;
            }
            goto L_error;
        case CHUNKED_IN_TRAILERS_LINE_HEAD:
            for (;; ++buf) {
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if (*buf != '\r') {
                    break;
                }
                ++buf;
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if (*buf != '\n') {
                    break;
                }
                ++buf;
                ret = -1; /* end of trailers */
                goto L_again;
            }
            decoder->_state = CHUNKED_IN_TRAILERS_LINE_MIDDLE;
        /* fall-through */
        case CHUNKED_IN_TRAILERS_LINE_MIDDLE:
            for (;; ++buf) {
                if (buf == buf_end) {
                    goto L_incomplete;
                }
                if (*buf == '\n') {
                    break;
                }
            }
            ++buf;
            decoder->_state = CHUNKED_IN_TRAILERS_LINE_HEAD;
            break;
        default:
            assert(false);
            break;
        }
    L_again:
        if (ret != -2)
            break;
    }

    ret = 0;
    goto L_exit;

L_error:
    ret = -1;
    goto L_exit;

L_incomplete:
    ret = -2;

L_exit:
    *_bufsz = buf - buf_start;
    return ret;
}

int phr_decode_chunked_is_in_data(struct phr_chunked_decoder *decoder) {
    return decoder->_state == CHUNKED_IN_CHUNK_DATA;
}

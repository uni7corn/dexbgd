#include "protocol.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

// ---------------------------------------------------------------------------
// JSON Parsing (inbound)
// ---------------------------------------------------------------------------

// Find "key" in JSON and return pointer to the character after the colon.
// Handles "key": with optional whitespace after colon.
static const char* find_key(const char* json, const char* key) {
    // Build "\"key\":" pattern
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char* p = json;
    while ((p = strstr(p, pattern)) != nullptr) {
        p += strlen(pattern);
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ':') {
            p++;
            // Skip whitespace after colon
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
    }
    return nullptr;
}

bool json_get_string(const char* json, const char* key, char* out, size_t out_len) {
    const char* p = find_key(json, key);
    if (!p || *p != '"') return false;
    p++; // skip opening quote

    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++; // skip backslash
            switch (*p) {
                case '"':  out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                case 'n':  out[i++] = '\n'; break;
                case 't':  out[i++] = '\t'; break;
                case '/':  out[i++] = '/'; break;
                default:   out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return true;
}

bool json_get_int(const char* json, const char* key, int* out) {
    const char* p = find_key(json, key);
    if (!p) return false;
    // Handle negative numbers
    if ((*p >= '0' && *p <= '9') || *p == '-') {
        *out = (int)strtol(p, nullptr, 10);
        return true;
    }
    return false;
}

bool json_get_long(const char* json, const char* key, long long* out) {
    const char* p = find_key(json, key);
    if (!p) return false;
    if ((*p >= '0' && *p <= '9') || *p == '-') {
        *out = strtoll(p, nullptr, 10);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// JSON Building (outbound)
// ---------------------------------------------------------------------------

// Escape a string for JSON output. Writes to out, returns chars written.
static int json_escape(const char* src, char* out, int out_len) {
    int pos = 0;
    if (!src) {
        if (out_len > 0) out[0] = '\0';
        return 0;
    }
    for (int i = 0; src[i] && pos < out_len - 2; i++) {
        char c = src[i];
        switch (c) {
            case '"':  if (pos + 2 < out_len) { out[pos++] = '\\'; out[pos++] = '"'; } break;
            case '\\': if (pos + 2 < out_len) { out[pos++] = '\\'; out[pos++] = '\\'; } break;
            case '\n': if (pos + 2 < out_len) { out[pos++] = '\\'; out[pos++] = 'n'; } break;
            case '\r': if (pos + 2 < out_len) { out[pos++] = '\\'; out[pos++] = 'r'; } break;
            case '\t': if (pos + 2 < out_len) { out[pos++] = '\\'; out[pos++] = 't'; } break;
            default:
                // Escape control characters as \u00XX
                if ((unsigned char)c < 0x20) {
                    if (pos + 6 < out_len) {
                        pos += snprintf(out + pos, out_len - pos, "\\u%04x", (unsigned char)c);
                    }
                } else {
                    out[pos++] = c;
                }
                break;
        }
    }
    out[pos] = '\0';
    return pos;
}

void json_start(JsonBuf* jb) {
    jb->pos = 0;
    jb->first = true;
    jb->buf[jb->pos++] = '{';
}

static void json_add_comma(JsonBuf* jb) {
    if (!jb->first) {
        jb->buf[jb->pos++] = ',';
    }
    jb->first = false;
}

void json_add_string(JsonBuf* jb, const char* key, const char* value) {
    json_add_comma(jb);
    char escaped[8192];
    json_escape(value, escaped, sizeof(escaped));
    jb->pos += snprintf(jb->buf + jb->pos, sizeof(jb->buf) - jb->pos,
                        "\"%s\":\"%s\"", key, escaped);
}

void json_add_int(JsonBuf* jb, const char* key, int value) {
    json_add_comma(jb);
    jb->pos += snprintf(jb->buf + jb->pos, sizeof(jb->buf) - jb->pos,
                        "\"%s\":%d", key, value);
}

void json_add_long(JsonBuf* jb, const char* key, long long value) {
    json_add_comma(jb);
    jb->pos += snprintf(jb->buf + jb->pos, sizeof(jb->buf) - jb->pos,
                        "\"%s\":%lld", key, value);
}

void json_add_bool(JsonBuf* jb, const char* key, bool value) {
    json_add_comma(jb);
    jb->pos += snprintf(jb->buf + jb->pos, sizeof(jb->buf) - jb->pos,
                        "\"%s\":%s", key, value ? "true" : "false");
}

void json_add_raw(JsonBuf* jb, const char* key, const char* raw_json) {
    json_add_comma(jb);
    jb->pos += snprintf(jb->buf + jb->pos, sizeof(jb->buf) - jb->pos,
                        "\"%s\":%s", key, raw_json);
}

void json_end(JsonBuf* jb) {
    if (jb->pos < (int)sizeof(jb->buf) - 2) {
        jb->buf[jb->pos++] = '}';
        jb->buf[jb->pos++] = '\n';
        jb->buf[jb->pos] = '\0';
    }
}

// ---------------------------------------------------------------------------
// Array building
// ---------------------------------------------------------------------------

void json_array_start(JsonArrayBuf* ab) {
    ab->pos = 0;
    ab->first = true;
    ab->buf[ab->pos++] = '[';
}

void json_array_add_object(JsonArrayBuf* ab, const char* obj_json) {
    if (!ab->first) {
        ab->buf[ab->pos++] = ',';
    }
    ab->first = false;
    int len = strlen(obj_json);
    if (ab->pos + len < (int)sizeof(ab->buf) - 2) {
        memcpy(ab->buf + ab->pos, obj_json, len);
        ab->pos += len;
    }
}

void json_array_end(JsonArrayBuf* ab) {
    if (ab->pos < (int)sizeof(ab->buf) - 1) {
        ab->buf[ab->pos++] = ']';
        ab->buf[ab->pos] = '\0';
    }
}

// ---------------------------------------------------------------------------
// Base64 encoding
// ---------------------------------------------------------------------------

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const unsigned char* data, int len, char* out, int out_len) {
    int pos = 0;
    int i;
    for (i = 0; i + 2 < len; i += 3) {
        if (pos + 4 >= out_len) break;
        unsigned int v = ((unsigned int)data[i] << 16) |
                         ((unsigned int)data[i+1] << 8) |
                         (unsigned int)data[i+2];
        out[pos++] = b64_table[(v >> 18) & 0x3F];
        out[pos++] = b64_table[(v >> 12) & 0x3F];
        out[pos++] = b64_table[(v >> 6) & 0x3F];
        out[pos++] = b64_table[v & 0x3F];
    }
    if (i < len && pos + 4 < out_len) {
        unsigned int v = (unsigned int)data[i] << 16;
        if (i + 1 < len) v |= (unsigned int)data[i+1] << 8;
        out[pos++] = b64_table[(v >> 18) & 0x3F];
        out[pos++] = b64_table[(v >> 12) & 0x3F];
        out[pos++] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[pos++] = '=';
    }
    out[pos] = '\0';
    return pos;
}

// ---------------------------------------------------------------------------
// Base64 decoding
// ---------------------------------------------------------------------------

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;  // standard '+' and URL-safe '-'
    if (c == '/' || c == '_') return 63;  // standard '/' and URL-safe '_'
    return -1;  // padding ('=') or invalid
}

int base64_decode(const char* in, int in_len, unsigned char* out, int out_max) {
    int out_pos = 0;
    int i = 0;
    while (i < in_len) {
        // Collect up to 4 valid base64 characters
        int vals[4] = {0, 0, 0, 0};
        int count = 0;
        bool hit_pad = false;
        while (count < 4 && i < in_len) {
            char c = in[i++];
            if (c == '=') { hit_pad = true; break; }
            int v = b64_val((unsigned char)c);
            if (v >= 0) vals[count++] = v;
            // else: skip whitespace or invalid chars
        }
        if (count == 0) break;
        // Decode the group
        if (out_pos < out_max)
            out[out_pos++] = (unsigned char)((vals[0] << 2) | (vals[1] >> 4));
        if (count >= 3 && out_pos < out_max)
            out[out_pos++] = (unsigned char)(((vals[1] & 0x0F) << 4) | (vals[2] >> 2));
        if (count >= 4 && out_pos < out_max)
            out[out_pos++] = (unsigned char)(((vals[2] & 0x03) << 6) | vals[3]);
        if (hit_pad) break;
    }
    return out_pos;
}

// ---------------------------------------------------------------------------
// Large string field locator (no-copy, for base64 fields)
// ---------------------------------------------------------------------------

const char* json_find_string(const char* json, const char* key, int* out_len) {
    const char* p = find_key(json, key);
    if (!p || *p != '"') return nullptr;
    p++;  // skip opening quote
    const char* start = p;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p + 1)) p++;  // skip escaped char
        p++;
    }
    *out_len = (int)(p - start);
    return start;
}

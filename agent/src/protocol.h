#ifndef DEXBGD_PROTOCOL_H
#define DEXBGD_PROTOCOL_H

#include <cstddef>

// ---------------------------------------------------------------------------
// JSON-lines protocol helpers
// Hand-rolled JSON: snprintf outbound, strstr-based inbound parsing.
// No external library — keeps binary small, matches existing code style.
// ---------------------------------------------------------------------------

// --- JSON Parsing (inbound) ---

// Extract a string value for "key":"value". Returns true if found.
// out is null-terminated, at most out_len-1 chars copied.
bool json_get_string(const char* json, const char* key, char* out, size_t out_len);

// Extract an integer value for "key":123. Returns true if found.
bool json_get_int(const char* json, const char* key, int* out);

// Extract a long value for "key":123456. Returns true if found.
bool json_get_long(const char* json, const char* key, long long* out);

// --- JSON Building (outbound) ---

// JsonBuf: simple buffer for building JSON objects.
// Usage:
//   JsonBuf jb;
//   json_start(&jb);
//   json_add_string(&jb, "type", "connected");
//   json_add_int(&jb, "pid", getpid());
//   json_end(&jb);
//   SendToClient(jb.buf);

struct JsonBuf {
    char buf[16384];
    int pos;
    bool first;  // true if no fields added yet (no leading comma needed)
};

void json_start(JsonBuf* jb);
void json_add_string(JsonBuf* jb, const char* key, const char* value);
void json_add_int(JsonBuf* jb, const char* key, int value);
void json_add_long(JsonBuf* jb, const char* key, long long value);
void json_add_bool(JsonBuf* jb, const char* key, bool value);

// Add a raw JSON value (e.g. an already-built array or object).
// The value is NOT quoted or escaped.
void json_add_raw(JsonBuf* jb, const char* key, const char* raw_json);

// Close the object and append newline. After this, jb->buf is ready to send.
void json_end(JsonBuf* jb);

// --- Array building helpers ---
// For building JSON arrays of objects inline within a JsonBuf.

struct JsonArrayBuf {
    char buf[16384];
    int pos;
    bool first;
};

void json_array_start(JsonArrayBuf* ab);
void json_array_add_object(JsonArrayBuf* ab, const char* obj_json);
void json_array_end(JsonArrayBuf* ab);

// --- Base64 encoding ---
// Encode binary data to base64. Returns number of chars written (excluding null).
int base64_encode(const unsigned char* data, int len, char* out, int out_len);

// --- Base64 decoding ---
// Decode base64 string (in_len chars) into out. Returns decoded byte count, or -1 on error.
// out_max must be >= (in_len * 3 / 4 + 3). Handles standard and URL-safe alphabets.
int base64_decode(const char* in, int in_len, unsigned char* out, int out_max);

// --- Large string field ---
// Locate a string field in JSON and return a pointer to its content (after opening quote),
// setting *out_len to the raw character count (up to closing quote). Does NOT unescape.
// Returns nullptr if key not found. Pointer is into the original json buffer — do not free.
// Suitable for base64 fields (no escape sequences) but NOT for general string fields.
const char* json_find_string(const char* json, const char* key, int* out_len);

#endif // DEXBGD_PROTOCOL_H

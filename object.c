// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = NULL;
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len + 1 >= sizeof(header)) return -1;

    size_t object_len = (size_t)header_len + 1 + len;
    uint8_t *object_buf = malloc(object_len);
    if (!object_buf) return -1;

    memcpy(object_buf, header, (size_t)header_len);
    object_buf[header_len] = '\0';
    if (len > 0) memcpy(object_buf + header_len + 1, data, len);

    compute_hash(object_buf, object_len, id_out);
    if (object_exists(id_out)) {
        free(object_buf);
        return 0;
    }

    char hex[HASH_HEX_SIZE + 1];
    char dir_path[512];
    char final_path[1024];
    hash_to_hex(id_out, hex);
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        free(object_buf);
        return -1;
    }
    object_path(id_out, final_path, sizeof(final_path));

    char tmp_path[1024];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s/.tmpXXXXXX", dir_path) >= (int)sizeof(tmp_path)) {
        free(object_buf);
        return -1;
    }
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(object_buf);
        return -1;
    }

    size_t written = 0;
    while (written < object_len) {
        ssize_t n = write(fd, object_buf + written, object_len - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            unlink(tmp_path);
            free(object_buf);
            return -1;
        }
        written += (size_t)n;
    }

    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        free(object_buf);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(tmp_path);
        free(object_buf);
        return -1;
    }
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        free(object_buf);
        return -1;
    }

    int dir_fd = open(dir_path, O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(object_buf);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long file_len = ftell(f);
    if (file_len <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    uint8_t *file_buf = malloc((size_t)file_len);
    if (!file_buf) {
        fclose(f);
        return -1;
    }
    if (fread(file_buf, 1, (size_t)file_len, f) != (size_t)file_len) {
        free(file_buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    ObjectID actual;
    compute_hash(file_buf, (size_t)file_len, &actual);
    if (memcmp(actual.hash, id->hash, HASH_SIZE) != 0) {
        free(file_buf);
        return -1;
    }

    uint8_t *nul = memchr(file_buf, '\0', (size_t)file_len);
    if (!nul) {
        free(file_buf);
        return -1;
    }

    size_t header_len = (size_t)(nul - file_buf);
    char header[64];
    if (header_len >= sizeof(header)) {
        free(file_buf);
        return -1;
    }
    memcpy(header, file_buf, header_len);
    header[header_len] = '\0';

    char type_str[16];
    size_t payload_len;
    if (sscanf(header, "%15s %zu", type_str, &payload_len) != 2) {
        free(file_buf);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(file_buf);
        return -1;
    }

    size_t actual_payload = (size_t)file_len - header_len - 1;
    if (payload_len != actual_payload) {
        free(file_buf);
        return -1;
    }

    void *out = malloc(payload_len > 0 ? payload_len : 1);
    if (!out) {
        free(file_buf);
        return -1;
    }
    if (payload_len > 0) memcpy(out, nul + 1, payload_len);

    *data_out = out;
    *len_out = payload_len;
    free(file_buf);
    return 0;
}

// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h>

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

typedef struct TreeNode {
    char name[256];
    int is_file;
    uint32_t mode;
    ObjectID hash;
    struct TreeNode *children;
    size_t child_count;
    size_t child_cap;
} TreeNode;

static TreeNode *tree_node_new(const char *name, int is_file) {
    TreeNode *node = calloc(1, sizeof(TreeNode));
    if (!node) return NULL;
    snprintf(node->name, sizeof(node->name), "%s", name ? name : "");
    node->is_file = is_file;
    return node;
}

static void tree_node_free_children(TreeNode *node) {
    if (!node) return;
    for (size_t i = 0; i < node->child_count; i++) {
        tree_node_free_children(&node->children[i]);
    }
    free(node->children);
    node->children = NULL;
    node->child_count = 0;
    node->child_cap = 0;
}

static void tree_node_free(TreeNode *node) {
    if (!node) return;
    tree_node_free_children(node);
    free(node);
}

static TreeNode *tree_node_find_child(TreeNode *node, const char *name) {
    for (size_t i = 0; i < node->child_count; i++) {
        if (strcmp(node->children[i].name, name) == 0) return &node->children[i];
    }
    return NULL;
}

static TreeNode *tree_node_add_child(TreeNode *parent, const char *name, int is_file) {
    if (parent->child_count == parent->child_cap) {
        size_t new_cap = parent->child_cap == 0 ? 8 : parent->child_cap * 2;
        TreeNode *new_children = realloc(parent->children, new_cap * sizeof(TreeNode));
        if (!new_children) return NULL;
        parent->children = new_children;
        parent->child_cap = new_cap;
    }
    TreeNode *child = &parent->children[parent->child_count++];
    memset(child, 0, sizeof(*child));
    snprintf(child->name, sizeof(child->name), "%s", name);
    child->is_file = is_file;
    return child;
}

static int write_tree_recursive(const TreeNode *node, ObjectID *id_out) {
    if (!node || !id_out) return -1;
    Tree tree = {0};
    if (node->child_count > MAX_TREE_ENTRIES) return -1;

    for (size_t i = 0; i < node->child_count; i++) {
        const TreeNode *child = &node->children[i];
        TreeEntry *entry = &tree.entries[tree.count++];

        snprintf(entry->name, sizeof(entry->name), "%s", child->name);
        if (child->is_file) {
            entry->mode = child->mode;
            entry->hash = child->hash;
        } else {
            ObjectID subtree_id;
            if (write_tree_recursive(child, &subtree_id) != 0) return -1;
            entry->mode = 0040000;
            entry->hash = subtree_id;
        }
    }

    void *data = NULL;
    size_t len = 0;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    if (!id_out) return -1;
    TreeNode *root = tree_node_new("", 0);
    if (!root) return -1;

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        if (errno == ENOENT) {
            int rc_empty = write_tree_recursive(root, id_out);
            tree_node_free(root);
            return rc_empty;
        }
        tree_node_free(root);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        size_t line_len = strlen(line);
        if (line_len == sizeof(line) - 1 && line[line_len - 1] != '\n') {
            fclose(f);
            tree_node_free(root);
            return -1;
        }

        uint32_t mode = 0;
        ObjectID hash;
        uint64_t mtime = 0;
        uint32_t size = 0;
        char hash_hex[HASH_HEX_SIZE + 1];
        char path_copy[512];
        if (sscanf(line, "%o %64s %" SCNu64 " %u %511[^\n]",
                   &mode, hash_hex, &mtime, &size, path_copy) != 5) {
            fclose(f);
            tree_node_free(root);
            return -1;
        }
        (void)mtime;
        (void)size;
        if (hex_to_hash(hash_hex, &hash) != 0) {
            fclose(f);
            tree_node_free(root);
            return -1;
        }

        TreeNode *current = root;
        char *saveptr = NULL;
        char *part = strtok_r(path_copy, "/", &saveptr);
        while (part) {
            if (part[0] == '\0') {
                fclose(f);
                tree_node_free(root);
                return -1;
            }
            char *next = strtok_r(NULL, "/", &saveptr);
            int is_file = (next == NULL);

            TreeNode *child = tree_node_find_child(current, part);
            if (!child) {
                child = tree_node_add_child(current, part, is_file);
                if (!child) {
                    fclose(f);
                    tree_node_free(root);
                    return -1;
                }
            }

            if (is_file) {
                if (!child->is_file) {
                    fclose(f);
                    tree_node_free(root);
                    return -1;
                }
                child->mode = mode;
                child->hash = hash;
            } else if (child->is_file) {
                fclose(f);
                tree_node_free(root);
                return -1;
            }

            current = child;
            part = next;
        }
    }
    fclose(f);

    int rc = write_tree_recursive(root, id_out);
    tree_node_free(root);
    return rc;
}
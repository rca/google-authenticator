#include "libgoogleauthenticator.h"

/* Given an input value, this function computes the hash code that forms the
 * expected authentication token.
 */
#ifdef TESTING
int compute_code(const uint8_t *secret, int secretLen, unsigned long value)
    __attribute__((visibility("default")));
#else
    int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
        uint8_t val[8];
        for (int i = 8; i--; value >>= 8) {
            val[i] = value;
        }
        uint8_t hash[SHA1_DIGEST_LENGTH];
        hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
        memset(val, 0, sizeof(val));
        int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
        unsigned int truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash  |= hash[offset + i];
        }
        memset(hash, 0, sizeof(hash));
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return truncatedHash;
    }
#endif

char *get_secret_filename(logger *log, const char *username, int *uid) {
    const char *spec = SECRET;

    // Obtain the user's id and home directory
    struct passwd pwbuf, *pw = NULL;
    char *buf = NULL;
    char *secret_filename = NULL;
    if (1) {
#ifdef _SC_GETPW_R_SIZE_MAX
        int len = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (len <= 0) {
            len = 4096;
        }
#else
        int len = 4096;
#endif
        buf = malloc(len);
        buf[0] = '\0';
        *uid = -1;
        if (buf == NULL ||
                getpwnam_r(username, &pwbuf, buf, len, &pw) ||
                !pw ||
                !pw->pw_dir ||
                *pw->pw_dir != '/') {
err:
            (*log)(LOG_ERR, "Failed to compute location of secret file: %s", buf);
            free(buf);
            free(secret_filename);
            return NULL;
        }
    }

    // Expand filename specification to an actual filename.
    if ((secret_filename = strdup(spec)) == NULL) {
        goto err;
    }
    int allow_tilde = 1;
    for (int offset = 0; secret_filename[offset];) {
        char *cur = secret_filename + offset;
        char *var = NULL;
        size_t var_len = 0;
        const char *subst = NULL;
        if (allow_tilde && *cur == '~') {
            var_len = 1;
            if (!pw) {
                goto err;
            }
            subst = pw->pw_dir;
            var = cur;
        } else if (secret_filename[offset] == '$') {
            if (!memcmp(cur, "${HOME}", 7)) {
                var_len = 7;
                if (!pw) {
                    goto err;
                }
                subst = pw->pw_dir;
                var = cur;
            } else if (!memcmp(cur, "${USER}", 7)) {
                var_len = 7;
                subst = username;
                var = cur;
            }
        }
        if (var) {
            size_t subst_len = strlen(subst);
            char *resized = realloc(secret_filename,
                    strlen(secret_filename) + subst_len);
            if (!resized) {
                goto err;
            }
            var += resized - secret_filename;
            secret_filename = resized;
            memmove(var + subst_len, var + var_len, strlen(var + var_len) + 1);
            memmove(var, subst, subst_len);
            offset = var + subst_len - resized;
            allow_tilde = 0;
        } else {
            allow_tilde = *cur == '/';
            ++offset;
        }
    }

  *uid = pw->pw_uid;
  free(buf);
  return secret_filename;
}

uint8_t *get_shared_secret(logger *log, const char *secret_filename,
                                  const char *buf, int *secretLen) {
  // Decode secret key
  int base32Len = strcspn(buf, "\n");
  *secretLen = (base32Len*5 + 7)/8;
  uint8_t *secret = malloc(base32Len + 1);
  if (secret == NULL) {
    *secretLen = 0;
    return NULL;
  }
  memcpy(secret, buf, base32Len);
  secret[base32Len] = '\000';
  if ((*secretLen = base32_decode(secret, secret, base32Len)) < 1) {
    (*log)(LOG_ERR,
            "Could not find a valid BASE32 encoded secret in \"%s\"",
            secret_filename);
    memset(secret, 0, base32Len);
    free(secret);
    return NULL;
  }
  memset(secret + *secretLen, 0, base32Len + 1 - *secretLen);
  return secret;
}

#ifdef TESTING
static time_t current_time;
void set_time(time_t t) __attribute__((visibility("default")));
void set_time(time_t t) {
  current_time = t;
}

time_t get_time(void) {
  return current_time;
}
#else
time_t get_time(void) {
  return time(NULL);
}
#endif

int get_timestamp(void) {
  return get_time() / 30;
}

int open_secret_file(logger *log, const char *secret_filename, Params *params,
                            const char *username,
                            int uid, off_t *size, time_t *mtime) {
  // Try to open "~/.google_authenticator"
  *size = 0;
  *mtime = 0;
  int fd = open(secret_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 ||
      fstat(fd, &sb) < 0) {
      (*log)(LOG_ERR, "Failed to read \"%s\"", secret_filename);
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  // Check permissions on "~/.google_authenticator"
  if ((sb.st_mode & 03577) != 0400 ||
      !S_ISREG(sb.st_mode) ||
      sb.st_uid != (uid_t)uid) {
    char buf[80];
    (*log)(LOG_ERR,
                "Secret file \"%s\" must only be accessible by %s",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  if (sb.st_size < 1 || sb.st_size > 64*1024) {
    (*log)(LOG_ERR, "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  *size = sb.st_size;
  *mtime = sb.st_mtime;
  return fd;
}

char *read_file_contents(logger *log, const char *secret_filename, int *fd,
                                off_t filesize) {
  // Read file contents
  char *buf = malloc(filesize + 1);
  if (!buf ||
      read(*fd, buf, filesize) != filesize) {
    close(*fd);
    *fd = -1;
    (*log)(LOG_ERR, "Could not read \"%s\"", secret_filename);
 error:
    if (buf) {
      memset(buf, 0, filesize);
      free(buf);
    }
    return NULL;
  }
  close(*fd);
  *fd = -1;

  // The rest of the code assumes that there are no NUL bytes in the file.
  if (memchr(buf, 0, filesize)) {
    (*log)(LOG_ERR, "Invalid file contents in \"%s\"", secret_filename);
    goto error;
  }

  // Terminate the buffer with a NUL byte.
  buf[filesize] = '\000';

  return buf;
}

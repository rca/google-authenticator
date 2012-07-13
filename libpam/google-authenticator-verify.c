#include "libgoogleauthenticator.h"

logger stderr_logger_wrapper() {
    int stderr_logger(int level, char *format, ...) {
        va_list args;
        va_start(args, format);

        vfprintf(stderr, format, args);

        va_end(args);

        return 0;
    }

    return &stderr_logger;
}

int main(int argc, char **argv) {
    int value = 0;
    int tm = get_timestamp();
    int window = 3;
    int skew = 0;

    struct passwd *pw;
    uid_t uid;
    char *username = NULL;

    char *secret_filename = NULL;
    char *buf = NULL;

    off_t size = 0;
    time_t mtime;
    int fd = 0;

    uint8_t *shared_secret = NULL;
    int secret_len = 0;

    if(argc < 2) {
        fprintf(stderr, "Code argument missing\n");
        exit(1);
    }

    unsigned int code = atoi(argv[1]);

    logger stderr_logger = stderr_logger_wrapper();

    Params params = { 0 };

    //printf("code: %d\n", code);

    uid = geteuid();
    pw = getpwuid(uid);
    if(!pw) {
        fprintf(stderr, "Unable to get username\n");
        exit(1);
    }

    username = pw->pw_name;

    secret_filename = get_secret_filename(&stderr_logger, username, &uid);

    fd = open_secret_file(&stderr_logger, secret_filename, &params, username, uid, &size, &mtime);
    buf = read_file_contents(&stderr_logger, secret_filename, &fd, size);

    shared_secret = get_shared_secret(&stderr_logger, secret_filename, buf, &secret_len);

    //printf("secret filename: %s\n", secret_filename, shared_secret);

    for (int i = -((window-1)/2); i <= window/2; ++i) {
        value = tm + skew + i;

        unsigned int t_code = compute_code(shared_secret, secret_len, value);
        //printf("i: %2d, tm: %d, value: %d, t_code: %06d\n", i, tm, value, t_code);

        if(t_code == code) {
            return 0;
        }
    }

    return 1;
}

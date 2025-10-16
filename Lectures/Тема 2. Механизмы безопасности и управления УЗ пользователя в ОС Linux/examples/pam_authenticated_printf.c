#include <unistd.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#ifdef DEBUG
#define DBG_PRINT(s) (s);
#else
#define DBG_PRINT(s) ;
#endif


void err_exit(const char *msg, int code) {
    perror(msg);
    exit(code);
}

int main(int argc, const char *argv[]) {
    const char *prog_name = argv[0];

    // get info about the user
    uid_t ruid = getuid();
    struct passwd *pwd = getpwuid(ruid);
    if (pwd == NULL) {
        err_exit("getpwuid failed", 2);
    }
    const char *user = pwd->pw_name;

    DBG_PRINT(printf("[DEBUG]  user=%s ruid=%d\n", user, ruid))

    // 1. init PAM
    struct pam_conv pamc = {&misc_conv, NULL};
    static pam_handle_t *pamh = NULL;
    if (pam_start(prog_name, user, &pamc, &pamh) != PAM_SUCCESS) {
        err_exit("pam_start failed", 3);
    }

    // 2. authenticate the user
    int pam_err, exit_code = 0;
    if ((pam_err = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
        fprintf(stderr, "pam_authenticate failed: %s\n", pam_strerror(pamh, pam_err));
        goto pamerr;
    }

    // 3. establish the requested credentials
    if ((pam_err = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
        perror("pam_setcred failed");
        goto pamerr;
    }

    // 4. authentication succeeded - open a session
    if ((pam_err = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
        fprintf(stderr, "pam_open_session failed: %s\n", pam_strerror(pamh, pam_err));
        goto pamerr;
    }

    printf("Authenticated printf :-)\n");

pamerr:
    exit_code = 4;
cleanup:
    // close the session and release PAM resources
    pam_err = pam_close_session(pamh, 0);
    pam_end(pamh, pam_err);
    return exit_code;
}

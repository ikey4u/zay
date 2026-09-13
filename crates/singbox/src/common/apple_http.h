#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct singbox_apple_http_session singbox_apple_http_session_t;
typedef struct singbox_apple_http_task singbox_apple_http_task_t;

typedef struct singbox_apple_http_session_config {
    const char *proxy_host;
    int proxy_port;
    const char *proxy_username;
    const char *proxy_password;
    uint16_t min_tls_version;
    uint16_t max_tls_version;
    bool insecure;
    const uint8_t **anchor_certificates;
    const size_t *anchor_certificate_lengths;
    size_t anchor_certificate_count;
    bool anchor_only;
    const uint8_t *pinned_public_key_sha256;
    size_t pinned_public_key_sha256_len;
} singbox_apple_http_session_config_t;

typedef struct singbox_apple_http_request {
    const char *method;
    const char *url;
    const char **header_keys;
    const char **header_values;
    size_t header_count;
    const uint8_t *body;
    size_t body_len;
    bool has_verify_time;
    int64_t verify_time_unix_millis;
} singbox_apple_http_request_t;

typedef struct singbox_apple_http_response {
    int status_code;
    char **header_keys;
    char **header_values;
    size_t header_count;
    uint8_t *body;
    size_t body_len;
} singbox_apple_http_response_t;

singbox_apple_http_session_t *singbox_apple_http_session_create(
    const singbox_apple_http_session_config_t *config,
    char **error_out
);
void singbox_apple_http_session_close(singbox_apple_http_session_t *session);

singbox_apple_http_task_t *singbox_apple_http_session_send_async(
    singbox_apple_http_session_t *session,
    const singbox_apple_http_request_t *request,
    char **error_out
);
singbox_apple_http_response_t *singbox_apple_http_task_wait(
    singbox_apple_http_task_t *task,
    char **error_out
);
void singbox_apple_http_task_cancel(singbox_apple_http_task_t *task);
void singbox_apple_http_task_close(singbox_apple_http_task_t *task);
void singbox_apple_http_response_free(singbox_apple_http_response_t *response);

char *singbox_apple_http_verify_public_key_sha256(
    const uint8_t *known_hash_values,
    size_t known_hash_values_len,
    const uint8_t *leaf_cert,
    size_t leaf_cert_len
);

#ifndef ZAY_IOS_H
#define ZAY_IOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void zay_ios_set_log_path(const char *path);
void zay_ios_log(const char *level, const char *message);
char *zay_ios_last_error(void);
void zay_ios_free_string(char *s);
char *zay_ios_build_easytier_toml(const char *input_json);
char *zay_ios_build_singbox_json(const char *input_json);
char *zay_ios_list_proxy_nodes(const char *proxy_url);
int32_t zay_ios_prefetch_proxy(const char *proxy_url, const char *working_dir);
char *zay_ios_convert_rule_text(const char *raw, const char *hint);
char *zay_ios_embedded_rules_info(const char *working_dir);
int32_t zay_ios_ensure_embedded_rules(const char *working_dir);
int32_t zay_ios_start_mesh(const char *toml);
int32_t zay_ios_stop_mesh(void);
char *zay_ios_mesh_status_json(void);
int32_t zay_ios_set_tun_fd(const char *inst_name, int32_t fd);
char *zay_ios_relay_host(const char *relay_url);

#ifdef __cplusplus
}
#endif

#endif /* ZAY_IOS_H */

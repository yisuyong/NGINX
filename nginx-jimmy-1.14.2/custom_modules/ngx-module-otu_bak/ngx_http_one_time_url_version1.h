#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static u_char *otu_run_version1(ngx_http_request_t *r,void *conf);

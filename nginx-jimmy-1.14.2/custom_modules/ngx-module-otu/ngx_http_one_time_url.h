static ngx_int_t ngx_http_one_time_url_init(ngx_conf_t *cf);
static void *ngx_http_one_time_url_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_one_time_url_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_one_time_url_handler(ngx_http_request_t *r);

static ngx_int_t otu_run_version1(ngx_http_request_t *r,void *conf);
static ngx_int_t otu_run_version2(ngx_http_request_t *r,void *conf);

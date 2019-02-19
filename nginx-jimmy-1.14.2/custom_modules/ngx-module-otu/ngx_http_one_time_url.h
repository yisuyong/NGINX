#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
http {
  server{
          otu_version 1; //version name
          otu_key "1234567890abcdfe";
          otu_iv "efdca0987654321";
          otu_param "jimmy";
          otu_bypass="*.ts";
  }
}
*/

typedef ngx_int_t *(*ngx_http_one_time_url_op_run_pt) (ngx_http_request_t *r,void *data);

typedef struct {
  ngx_uint_t version;
  ngx_str_t key;
  ngx_str_t iv;
  ngx_str_t bypass;
  ngx_str_t param;

  ngx_http_one_time_url_op_run_pt run;
} ngx_http_one_time_url_loc_conf_t;


static ngx_int_t ngx_http_one_time_url_init(ngx_conf_t *cf);
static void *ngx_http_one_time_url_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_one_time_url_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_one_time_url_handler(ngx_http_request_t *r);

static ngx_int_t *otu_run_version1(ngx_http_request_t *r,void *conf);
static ngx_int_t *otu_run_version2(ngx_http_request_t *r,void *conf);

#include "ngx_http_one_time_url.h"

static ngx_command_t  ngx_http_one_time_url_commands[] = {

  { ngx_string("otu_version"), 
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_one_time_url_loc_conf_t, version),
    NULL },
  {
    ngx_string("otu_key"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_one_time_url_loc_conf_t, key),
    NULL
  },
  {
    ngx_string("otu_iv"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_one_time_url_loc_conf_t, iv),
    NULL
  },
  {
    ngx_string("otu_bypass"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_one_time_url_loc_conf_t, bypass),
    NULL
  },
  ngx_null_command
};



static ngx_http_module_t ngx_http_one_time_url_module_ctx = {
  NULL, /* preconfiguration */
  ngx_http_one_time_url_init, /* postconfiguration */
  NULL, /* create main configuration */
  NULL, /* init main configuration */
  NULL, /* create server configuration */
  NULL, /* merge server configuration */
  ngx_http_one_time_url_create_loc_conf,    /* create location configuration */
  ngx_http_one_time_url_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_one_time_url_module = {
    NGX_MODULE_V1,
    &ngx_http_one_time_url_module_ctx,            /* module context */
    ngx_http_one_time_url_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_one_time_url_handler(ngx_http_request_t *r)
{

   ngx_http_one_time_url_loc_conf_t *olcf;

   olcf=ngx_http_get_module_loc_conf(r,ngx_http_one_time_url_module);

   olcf->run(r,olcf);
   //return NGX_DECLINED;
   return NGX_OK;

}



static void *ngx_http_one_time_url_create_loc_conf(ngx_conf_t *cf)
{

  ngx_http_one_time_url_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_one_time_url_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->version = NGX_CONF_UNSET;
  
  return conf;

}


static char *ngx_http_one_time_url_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_one_time_url_loc_conf_t  *prev = parent;
    ngx_http_one_time_url_loc_conf_t  *conf = child;

    if (conf->version >= 1) 
    {
	ngx_conf_merge_uint_value(conf->version, prev->version, 1);
	ngx_conf_merge_str_value(conf->key, prev->key, "1234567890abcdfe");
	ngx_conf_merge_str_value(conf->iv, prev->iv, "efdca0987654321");
	ngx_conf_merge_str_value(conf->bypass, prev->bypass, "*.ts");

	if(conf->version ==1)
	{
		conf->run=otu_run_version1;
        }
	else
	{
		conf->run=otu_run_version2;
	}

	return NGX_CONF_OK;
    }
   else
   {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
            "otu version must be equal or more than 1");
   }

   return NGX_CONF_ERROR;

}


static ngx_int_t ngx_http_one_time_url_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cscf;

  cscf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module); 

  h = ngx_array_push(&cscf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_one_time_url_handler;

  return NGX_OK;
}



static ngx_int_t *otu_run_version1(ngx_http_request_t *r,void *conf)
{
        ngx_http_one_time_url_loc_conf_t *olcf;

        olcf=(ngx_http_one_time_url_loc_conf_t *) conf;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler version %i, key : %s, iv : %s, bypass : %s, uri : %s",
                   olcf->version,olcf->key.data,olcf->iv.data,olcf->bypass.data,r->uri.data);
	return NGX_OK;
}


static ngx_int_t *otu_run_version2(ngx_http_request_t *r,void *conf)
{
        ngx_http_one_time_url_loc_conf_t *olcf;

        olcf=(ngx_http_one_time_url_loc_conf_t *) conf;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler version %i, key : %s, iv : %s, bypass : %s, uri : %s",
                   olcf->version,olcf->key.data,olcf->iv.data,olcf->bypass.data,r->uri.data);
	return NGX_OK;
}


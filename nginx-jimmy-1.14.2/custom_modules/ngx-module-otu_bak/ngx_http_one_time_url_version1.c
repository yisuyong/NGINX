#include "ngx_http_one_time_url.h"
#include "ngx_http_one_time_url_version1.h"
  
static u_char *otu_run_version1(ngx_http_request_t *r,void *conf)
{
	ngx_http_one_time_url_loc_conf_t *olcf;
	
	olcf=(ngx_http_one_time_url_loc_conf_t *)conf;

	return "version ok";

}

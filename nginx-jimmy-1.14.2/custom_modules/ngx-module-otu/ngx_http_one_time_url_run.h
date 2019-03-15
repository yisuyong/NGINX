ngx_int_t vaild_check_otu(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf, ngx_str_t *host,ngx_str_t *uri,ngx_str_t *args,ngx_str_t *data);
u_char *explode_find_queryString(ngx_http_request_t *r,ngx_str_t *src,ngx_str_t *findstr,u_char delimiter);
ngx_int_t otu_run_version1_decrypt(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf);
ngx_int_t remove_querystring(ngx_http_request_t *r,u_char *remove_str,ngx_str_t *src_str);

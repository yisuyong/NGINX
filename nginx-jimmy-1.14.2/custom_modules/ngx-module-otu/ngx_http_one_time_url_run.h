ngx_int_t vaild_check_otu(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf,ngx_str_t *uri,ngx_str_t *data,ngx_str_t *host);
u_char *find_querystring(ngx_http_request_t *r,ngx_str_t *findstr,u_char *src_str);
ngx_int_t otu_run_version1_decrypt(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf);

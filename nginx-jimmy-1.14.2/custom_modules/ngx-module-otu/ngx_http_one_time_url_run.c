#include "ngx_http_one_time_url_conf.h"
#include "ngx_http_one_time_url_run.h"
#include "ngx_http_one_time_url_b64.h"

#include <openssl/aes.h>

ngx_int_t ngx_http_one_time_url_deny(ngx_http_request_t *r)
{
    ngx_buf_t *b;
    ngx_chain_t out;

    u_char message[]="Unauthorized.";

    ngx_int_t rc;

    /* Set the Content-Type header. */
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = message; /* first position in memory of the data */
    b->last = message + sizeof(message); /* last position in memory of the data */
    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_UNAUTHORIZED; /* 401 status code */
    /* Get the content length of the body. */
    r->headers_out.content_length_n = sizeof(message);
    ngx_http_send_header(r); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    rc=ngx_http_output_filter(r, &out);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler session termination rc value : %i",rc);
    return NGX_ERROR;

} /* ngx_http_hello_world_handler */


ngx_int_t current_time_check(ngx_http_request_t *r,u_char *vaildtime)
{
        time_t  timestamp=ngx_time();
        ssize_t limit;
        ssize_t cur;

        struct tm *timeinfo;
        char buffer[15];

        memset(buffer, 0x00,sizeof(buffer));
        time(&timestamp);
        timeinfo=localtime(&timestamp);

        strftime(buffer,15,"%Y%m%d%H%M%S",timeinfo);

        cur=ngx_atosz((u_char *)buffer,ngx_strlen(buffer));
        limit=ngx_atosz(vaildtime,ngx_strlen(vaildtime));

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler current : %i vaildtime: %i ",cur,limit);

        if(cur<=limit)
	{
                return NGX_OK;
	}

        return NGX_ERROR;
}




ngx_int_t vaild_check_otu(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf,ngx_str_t *uri,ngx_str_t *data,ngx_str_t *host)
{

//	data=P9Rq1NqjqK0jzAUdMC13xoulxTMxxM2C+Sw1e95b15w=
//	uri=/a.png
//	host=www.zexter.org:8080

        AES_KEY dec_key;

	u_char *key,*iv;
	u_char *dec_out, *b64_dec;

	size_t	dec_out_len=host->len + uri->len + 25; //(?validtime=20190101121212)


	u_char *vaildtime;
	ngx_str_t str_temp;


	key = ngx_palloc(r->pool,AES_BLOCK_SIZE+1);
	iv = ngx_palloc(r->pool,AES_BLOCK_SIZE+1);

	dec_out = ngx_palloc(r->pool,dec_out_len);

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler test size %d + %d + 25 = %d",host->len,uri->len,dec_out_len );
	if(dec_out == NULL || key == NULL || iv == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler palloc error" );
		return NGX_ERROR;
	}


        memset(dec_out, 0x00, data->len);
        memset(key, 0x00, AES_BLOCK_SIZE+1);
        memset(iv, 0x00, AES_BLOCK_SIZE+1);

	ngx_cpystrn(key,conf->key.data,AES_BLOCK_SIZE+1);
	ngx_cpystrn(iv,conf->iv.data,AES_BLOCK_SIZE+1);


	b64_dec=b64_decode(data);

        AES_set_decrypt_key(key, 128, &dec_key); // Size of key is in bits
        AES_cbc_encrypt(b64_dec, dec_out, dec_out_len, &dec_key, iv, AES_DECRYPT);

	if(b64_dec != NULL)
	{
		free(b64_dec);
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler Decode data : %s", dec_out);


	ngx_str_set(&str_temp,"vaildtime");
	str_temp.len=9;

	vaildtime=find_querystring(r,&str_temp,dec_out);
	if(vaildtime != NULL)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime: %s",vaildtime);
	}


	if(current_time_check(r,vaildtime)==0)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime: %s OK!!",vaildtime);
		return NGX_OK;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime: %s invaild",vaildtime);

/*

	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler time : %T uri : %V, args: %V, Host: %V",
                  ngx_time(),uri,data,host);
*/


	return NGX_ERROR;

}


u_char *find_querystring(ngx_http_request_t *r,ngx_str_t *findstr,u_char *src_str)
{

//	args=test=123&ajc=1&jimmy=d3d3LnpleHRlci5vcmcvYS5wbmc/dmFpbGR0aW1lPTEyMzIxMw==
	
	ngx_str_t *args = &r->args;
	u_char *query=args->data;

	if(src_str !=NULL)
	{
		query=src_str;
	}

	ngx_uint_t param_len=findstr->len + 1;
	u_char param[param_len];


	u_char buffer[param_len];
	u_char find;


	ngx_uint_t i,n=1,flag=0;

	ngx_snprintf(param,param_len,"%s=",findstr->data);

	while(n <= args->len)
	{

		find=*query;

		if(find == param[0])
		{
			for(i=0;i<param_len;i++)
			{
				buffer[i]=*query++;
				n++;

				if(buffer[i]==' ')
				{
					for(;i<param_len;i++)
					{
						buffer[i]='\0';
					}
					break;
				}
			}

		}
		else
		{
			query++;
			n++;
			continue;
		}

		if(!ngx_strncmp(buffer,param,param_len))
		{
//			ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler test1 find %s \t %i/%i",buffer,n,args->len);
			flag=1;
			break;	
		}
	}

	if(flag)
	{

		u_char *temp=query;
		ngx_uint_t temp_len=ngx_strlen(temp);
		u_char encrypt_data[temp_len];
		
		u_char d;

		u_char *return_value;


		n=0;

		while(*temp)
		{
			d=*temp++;

			if(d == ' ' || d =='&')
			{
				encrypt_data[n]='\0';
				break;
			}
			else
			{
				encrypt_data[n]=d;
				n++;
			}
		}

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Find OTU Encrypt QueryString %s / (%i)",encrypt_data,ngx_strlen(encrypt_data));

		return_value=ngx_palloc(r->pool,ngx_strlen(encrypt_data));

		if(return_value == NULL)
		{
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Can't palloc : %s",encrypt_data);
			return NULL;
		}
		
		ngx_sprintf(return_value,"%s",encrypt_data);

		return return_value;
	}

	else
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Not Find OTU QueryString : %s",param);
	}

	return NULL;


}

ngx_int_t otu_run_version1_decrypt(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf)
{
	ngx_str_t uri;
	ngx_str_t data;
	ngx_str_t host;

	u_char *temp_str=NULL;

	ngx_log_debug7(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler version %i, key : %V, iv : %V, bypass : %V,param : %V, uri : %V, args : %V",
                   conf->version,&conf->key,&conf->iv,&conf->bypass,&conf->param,&r->uri,&r->args);

	ngx_str_set(&host,r->headers_in.host->value.data);
	host.len=r->headers_in.host->value.len;

	ngx_str_set(&uri,r->uri.data);
	uri.len=r->uri.len;

	
	ngx_str_null(&data);
	data.len=0;

	temp_str=find_querystring(r,&conf->param,NULL);

	if(temp_str != NULL)
	{
		ngx_str_set(&data,temp_str);
		data.len=ngx_strlen(temp_str);
	}
	else
	{
		return ngx_http_one_time_url_deny(r);
	}

	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler time : %T uri : %V, data: %V, Host: %V",
                  ngx_time(),&uri,&data,&host);

	if(vaild_check_otu(r,conf,&uri,&data,&host)==0)
	{
		//vaildtime 빼고 uri 다시 만들어 적용해야함
		return NGX_OK;
	}

	return ngx_http_one_time_url_deny(r);
}

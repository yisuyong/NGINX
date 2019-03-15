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




ngx_int_t vaild_check_otu(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf, ngx_str_t *host,ngx_str_t *uri,ngx_str_t *args,ngx_str_t *data)
{

//	data=P9Rq1NqjqK0jzAUdMC13xoulxTMxxM2C+Sw1e95b15w=
//	uri=/a.png

//	host=www.zexter.org:8080

        AES_KEY dec_key;

	u_char *key,*iv;
	u_char *dec_out, *b64_dec;
	u_char *dec_out_check;

	size_t	dec_out_len=host->len + uri->len + 25; //(?validtime=20190101121212)


	u_char *vaildtime;
	u_char vaild_str[1024];


	u_char *vaild_url;
	ngx_uint_t vaild_url_len = host->len + uri->len;
	u_char vaild_url_str[vaild_url_len +1];



	key = ngx_palloc(r->pool,AES_BLOCK_SIZE+1);
	iv = ngx_palloc(r->pool,AES_BLOCK_SIZE+1);

	dec_out = ngx_palloc(r->pool,dec_out_len);

//	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler test size %d + %d + 25 = %d",host->len,uri->len,dec_out_len );
	if(dec_out == NULL || key == NULL || iv == NULL || data == NULL)
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

	if(dec_out == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Decrypt  error" );
		return NGX_ERROR;
	}


	dec_out_check=dec_out;

	for(ngx_uint_t i=0; i < dec_out_len;i++)
	{
		u_char p=*(dec_out_check++);

		if( p > 127)
		{	
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Decrpyt error");
			return NGX_ERROR;
		
		}
	}
		
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                	   "suyong OTU Handler Decode data : %s", dec_out);


        memset(vaild_str, 0x00,sizeof(vaild_str));
	ngx_sprintf(vaild_str,"%s=\0","vaildtime");

	vaildtime=(u_char *)ngx_strstr(dec_out,vaild_str);
	
	vaildtime=vaildtime+ngx_strlen(vaild_str);

	if(vaildtime != NULL)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime: %s",vaildtime);
	}

        memset(vaild_url_str, 0x00,sizeof(vaild_url_str));
	ngx_sprintf(vaild_url_str,"%V%V",host,uri);

	vaild_url=(u_char *)ngx_strstr((char *)dec_out,(char *)vaild_url_str);
	if(vaild_url == NULL)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler error vaild_url different: %s ",vaild_url_str);
		return NGX_ERROR;
	}
	

	if(current_time_check(r,vaildtime)==0)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime: %s OK!!",vaildtime);
		return NGX_OK;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime: %s invaild",vaildtime);


	return NGX_ERROR;

}

ngx_int_t remove_querystring(ngx_http_request_t *r,u_char *remove_str,ngx_str_t *src_str)
{

	// & 구분자로 explode 구현해서 다시 만들어야함

	ngx_int_t len=src_str->len + 1;
	u_char src_temp[len];
	u_char src_last[len];

	ngx_int_t r_len=(ngx_int_t)ngx_strlen(remove_str);

        memset(src_temp, 0x00,sizeof(src_temp));
        memset(src_last, 0x00,sizeof(src_last));

	ngx_snprintf(src_temp,len,"%V\0",src_str);


	for(ngx_int_t i=0,z=0;i < len -1 ;i++)
	{

		u_char p1=*remove_str;

		if(src_temp[i] == p1)
		{
			u_char temp[r_len + 1];
			ngx_int_t j=i;

			memset(temp,0x00,sizeof(temp));

			for(ngx_int_t x=0;x<r_len;x++,j++)
			{
				temp[x]=src_temp[j];
			}
			temp[r_len+1]='\0';

			if(!ngx_strncmp((char *)temp,(char *)remove_str,r_len))
			{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                	   "suyong OTU Handler test1 : %s",temp);
			    
				i=i+r_len;
				continue;
			}
		}
		src_last[z]=src_temp[i];
		z++;
	}
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               	   "suyong OTU Handler test2 : %s",src_last);


	return NGX_OK;
}


u_char *explode_find_queryString(ngx_http_request_t *r,ngx_str_t *src,ngx_str_t *findstr,u_char delimiter)
{

	ngx_int_t i,z;
	ngx_uint_t params_count=0;
	u_char *temp;
	
	ngx_int_t len = src->len;
	u_char buffer[len+1];

	u_char *return_value;

	if(len<=0) return NULL;

/*	src->data = "a=123&ajc" src-len=9 */
	temp=src->data;

	params_count=1;
	memset(buffer,0x00,sizeof(buffer));
	for(i=0,z=0;i<len;i++)
	{
		u_char p=*(temp++);	
		
		if( p == delimiter )
		{
			params_count += 1;
			buffer[z]='\0';
			z=0;
			
			if(!ngx_strncmp(buffer,findstr->data,findstr->len))
			{
				if((return_value=ngx_palloc(r->pool,ngx_strlen(buffer)+1))!=NULL)
				{
					
					ngx_cpystrn(return_value,buffer,ngx_strlen(buffer)+1);
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler find string: %s",return_value);


					return return_value;
				}
				else
				{
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Error find string: %s, ngx_palloc failed",buffer);
					return NULL;
				}
			}
		}
		else
		{
			buffer[z]=p;
			z++;
		}
	}
	buffer[z]='\0';

	if(!ngx_strncmp(buffer,findstr->data,findstr->len))
	{

		if((return_value=ngx_palloc(r->pool,ngx_strlen(buffer)+1))!=NULL)
		{
			ngx_cpystrn(return_value,buffer,ngx_strlen(buffer)+1);
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler find string: %s",return_value);

			return return_value;
		}
		else
		{
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Error find string: %s, ngx_palloc failed",buffer);
			return NULL;
		}
	}
	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler Can't found String : %V / %V / %c / %d",src,findstr,delimiter);

	return NULL;
}



ngx_int_t otu_run_version1_decrypt(ngx_http_request_t *r,ngx_http_one_time_url_loc_conf_t *conf)
{
	ngx_str_t uri;
	ngx_str_t data;
	ngx_str_t host;
	ngx_str_t args;

	u_char *temp_str;
	u_char temp_str_array[1024];

	ngx_str_t temp_str2;

	

	ngx_log_debug7(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler version %i, key : %V, iv : %V, bypass : %V,param : %V, uri : %V, args : %V",
                   conf->version,&conf->key,&conf->iv,&conf->bypass,&conf->param,&r->uri,&r->args);

	ngx_str_set(&host,r->headers_in.host->value.data);
	host.len=r->headers_in.host->value.len;

	ngx_str_set(&uri,r->uri.data);
	uri.len=r->uri.len;

	ngx_str_set(&args,r->args.data);
	args.len=r->args.len;
	
	ngx_str_null(&data);
	data.len=0;

	temp_str2.data=explode_find_queryString(r,&r->args,&conf->param,'&');

	if(temp_str2.data == NULL)
	{
		return ngx_http_one_time_url_deny(r);
	}

	temp_str2.len=ngx_strlen(temp_str2.data);

        memset(temp_str_array, 0x00,sizeof(temp_str_array));
	ngx_sprintf(temp_str_array,"%V=\0",&conf->param);

	temp_str=(u_char*)ngx_strstr(temp_str2.data,temp_str_array);

	temp_str=temp_str+conf->param.len+1;

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
                   "suyong OTU Handler times : %T uri : %V, data: %V, Host: %V",
                  ngx_time(),&uri,&data,&host);

	if(vaild_check_otu(r,conf,&host,&uri,&args,&data)==0)
	{
		//vaildtime 빼고 uri 다시 만들어 적용해야함

		ngx_uint_t temp_len= data.len + conf->param.len + 2;
		u_char temp_str[temp_len];
	

		ngx_snprintf(temp_str,temp_len,"%s=%s\0",conf->param.data,data.data);
	
		remove_querystring(r,temp_str,&r->unparsed_uri);


/*
		ngx_str_set(&r->unparsed_uri,"/b.png");
		r->unparsed_uri.len=6;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler test : %V",
                  &r->unparsed_uri);
*/
		return NGX_OK;
	}

	return ngx_http_one_time_url_deny(r);
}

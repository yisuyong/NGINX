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
	u_char *b64_dec;
	u_char *dec_out_check;
	u_char *dec_out_check_tail;

	size_t	dec_out_len=host->len + uri->len +args->len+ 25; //(?validtime=20190101121212)

	u_char *dec_out;
	u_char dec_out_last[dec_out_len];

	u_char *vaildtime;
	u_char vaild_str[1024];

	ngx_uint_t url_len;

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

	dec_out_check_tail=(u_char *)ngx_strstr((char *)dec_out_check,"vaildtime=");

	memset(dec_out_last,0x00,sizeof(dec_out_last));


	for(ngx_uint_t i=0,y=0; i < dec_out_len;i++)
	{
		u_char p=*(dec_out_check++);

		if( p > 127)
		{	
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler data invaild Decrpyt error");
			return NGX_ERROR;
		}

		if(dec_out_check==dec_out_check_tail)
		{
			y=1;
			
		}

		if(y)
		{
			if(y>24) //validtime=20190101121212
			{
				dec_out_last[i]=p;
				dec_out_last[i+1]='\0';
				break;
			}

			//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler test1 Decrpyt: %c",p);

			dec_out_last[i]=p;
			y++;
		}
		else
		{
			dec_out_last[i]=p;
		}
	}
		
	dec_out = dec_out_last;

/*
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                	   "suyong OTU Handler Decode buf data : %s", dec_out_last);
*/
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                	   "suyong OTU Handler Decode *data : %s", dec_out);


        memset(vaild_str, 0x00,sizeof(vaild_str));
	ngx_sprintf(vaild_str,"%s=\0","vaildtime");

	vaildtime=(u_char *)ngx_strstr(dec_out,vaild_str);
	
	vaildtime=vaildtime+ngx_strlen(vaild_str);

	if(vaildtime == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaildtime error");
		return NGX_ERROR;
	}



	//url check
/*
        memset(vaild_url_str, 0x00,sizeof(vaild_url_str));
	ngx_sprintf(vaild_url_str,"%V%V",host,uri);

	vaild_url=(u_char *)ngx_strstr((char *)dec_out,(char *)vaild_url_str);
	if(vaild_url == NULL)
	{
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler error vaild_url different: %s / %s ",vaild_url_str,dec_out);
		return NGX_ERROR;
	}
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler vaild_url : %s / %s ",vaild_url_str,dec_out);
*/
        memset(vaild_url_str, 0x00,sizeof(vaild_url_str));
	ngx_sprintf(vaild_url_str,"%V%V",host,uri);
	vaild_url=(u_char *)ngx_strstr((char *)dec_out,(char *)vaild_url_str);
	if(vaild_url == NULL)
	{
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler error vaild_url different: %s / %s ",vaild_url_str,dec_out);
		return NGX_ERROR;
	}


	for(url_len=0;url_len<ngx_strlen(vaild_url);url_len++)
	{
		u_char p=*(vaild_url++);
		if(p == '?')
		{
			break;
		}	
	}

	if(ngx_strlen(vaild_url_str) != url_len)
	{
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"suyong OTU Handler error vaild_url different2: %s / %s ",vaild_url_str,dec_out);
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

	ngx_int_t len=src_str->len;
	u_char src[len + 1];
	u_char *src_tail;
	u_char src_head[len+1];
	

	u_char src_last_len=src_str->len - ngx_strlen(remove_str);
	u_char src_last[src_last_len +1];

	u_char *p;
	u_char *p2;
	ngx_int_t i;
	
	memset(src_last,0x00,sizeof(src_last));
	memset(src_head,0x00,sizeof(src_head));
	memset(src,0x00,sizeof(src));

	ngx_sprintf(src,"%V\0",src_str);

	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               	   "suyong OTU Handler Remove str: %s(%d) / src_str : %s(%d)",remove_str,ngx_strlen(remove_str),src,ngx_strlen(src));

	p=(u_char*)ngx_strstr((char *)src,(char *)remove_str);
	src_tail=p + ngx_strlen(remove_str);

	p2=src;

	for(i=0;i<len;i++)
	{
		u_char temp;
		temp=*p2;

		if(p2 == p)
		{
//			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,   "suyong OTU Handler test url head end");
			if(src_head[i-1]=='&')
			{
				src_head[i-1]='\0';
			}
			else
			{
				src_head[i]='\0';
			}
			break;
		}
		src_head[i]=temp;
		p2++;	
	}

	if(i==0)
	{
		src_tail++;
	}

	ngx_sprintf(src_last,"%s%s\0",src_head,src_tail);
	

	src_str->data=src_last;
	src_str->len=ngx_strlen(src_last);

/*
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               	   "suyong OTU Handler removed uri : %s",src_last );
*/
	
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

	u_char *unparsed_uri_modify;

	

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
                   "suyong OTU Handler ngx_current_time : %T uri : %V, data: %V, Host: %V",
                  ngx_time(),&uri,&data,&host);

	if(vaild_check_otu(r,conf,&host,&uri,&args,&data)==0)
	{
		ngx_uint_t temp_len=data.len + conf->param.len + 2;
		u_char temp_str[temp_len];
	
		memset(temp_str,0x00,sizeof(temp_str));

		ngx_snprintf(temp_str,temp_len,"%V=%V\0",&conf->param,&data);

/*
	ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler test1(%d)  %s(%d) / %s(%d)",temp_len,temp_str,ngx_strlen(temp_str),data.data,ngx_strlen(data.data));
*/	
		remove_querystring(r,temp_str,&args);


/*
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "suyong OTU Handler test1  unpared uri: %V",
                  &r->unparsed_uri);
*/


		u_char unparsed_uri_modify_buf[args.len + uri.len + 1 +1];
		memset(unparsed_uri_modify_buf,0x00,sizeof(unparsed_uri_modify_buf));

		if(args.len>0 && uri.len>0)
		{
			ngx_sprintf(unparsed_uri_modify_buf,"%V?%V\0",&uri,&args);
		}
		else if(args.len>0 && uri.len<=0)
		{
			ngx_sprintf(unparsed_uri_modify_buf,"/?%V\0",&args);
		}
		else
		{
			ngx_sprintf(unparsed_uri_modify_buf,"%V\0",&uri);
		}

		unparsed_uri_modify = ngx_palloc(r->pool,ngx_strlen(unparsed_uri_modify_buf)); 

		if(unparsed_uri_modify == NULL)
		{
			ngx_log_debug0(NGX_LOG_ERR, r->connection->log, 0, "suyong OTU Handler unparsed_uri_modify palloc failed");
			return ngx_http_one_time_url_deny(r);
		}
	
		ngx_cpystrn(unparsed_uri_modify,unparsed_uri_modify_buf,ngx_strlen(unparsed_uri_modify_buf)+1);

		r->unparsed_uri.data=unparsed_uri_modify;
		r->unparsed_uri.len=ngx_strlen(unparsed_uri_modify);
	

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        	           "suyong OTU Handler unparsed_uri_mod: %V",
                	  &r->unparsed_uri);

		return NGX_OK;
	}
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
       	           "suyong OTU Handler decrypt failed");

	return ngx_http_one_time_url_deny(r);
}

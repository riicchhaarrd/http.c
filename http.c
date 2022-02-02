//compile for linux
//gcc -g -I../rhd http.c

//cross compile exe
//x86_64-w64-mingw32-gcc http.c -I../rhd -lwsock32 -lws2_32

#define memory_allocate malloc
#define memory_deallocate free

#define HEAP_STRING_IMPL
#include "heap_string.h"

#define LINKED_LIST_IMPL
#include "linked_list.h"

#define HASH_MAP_IMPL
#include "hash_map.h"

#define STREAM_PARSE_IMPL
#include "stream_parse.h"

#include <signal.h>
#include <time.h>

#include <errno.h>
#include <sys/stat.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include "base64.h"

static int uploads_enabled = 0;

int read_binary_file(const char* path, unsigned char** pdata, size_t* size)
{
	FILE *fp = fopen(path, "rb");
	if(!fp) return 1;
	fseek(fp, 0, SEEK_END);
	*size = (size_t)ftell(fp);
	rewind(fp);
	unsigned char *data = malloc(*size);
	if(!data)
	{
		fclose(fp);
		return 3;
	}
	if(fread(data, 1, *size, fp) != *size)
	{
		free(data);
		fclose(fp);
		return 2;
	}
	*pdata = data;
	fclose(fp);
	return 0;
}

int read_text_file(const char* path, unsigned char** pdata, size_t* size)
{
	FILE *fp = fopen(path, "r");
	if(!fp) return 1;
	fseek(fp, 0, SEEK_END);
	*size = (size_t)ftell(fp);
	rewind(fp);
	unsigned char *data = malloc(*size + 1);
	if(!data)
	{
		fclose(fp);
		return 3;
	}
	if(fread(data, 1, *size, fp) != *size)
	{
		free(data);
		fclose(fp);
		return 2;
	}
	data[*size] = '\0';
	*pdata = data;
	fclose(fp);
	return 0;
}

#define LOG_MESSAGE(...)

volatile int listening = 1;
volatile int sock = 0;

void stop_server(int sig)
{
	listening = 0;
	close(sock);
}

heap_string build_http_header(const char *content_type, int status_code, const char *status_message, const char *data, size_t data_size, int keep_alive)
{
	heap_string header = NULL;
	heap_string_appendf(&header, "HTTP/1.1 %d %s\r\n", status_code, status_message);
	
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char s[64];
    assert(strftime(s, sizeof(s), "%a, %d %b %Y %H:%M:%S %Z", tm));
	heap_string_appendf(&header, "Date: %s\r\n", s);
	heap_string_appendf(&header, "Server: custom http server\r\n");
	
	heap_string_appendf(&header, "Content-Type: %s; charset=UTF-8\r\n", content_type);
	heap_string_appendf(&header, "Content-Length: %d\r\n", data_size);
	heap_string_appendf(&header, "Referrer-Policy: no-referrer\r\n");
	
	int caching = 0;
	
	if(!caching)
	{
		heap_string_appendf(&header, "Cache-control: no-cache\r\n");
		heap_string_appendf(&header, "Pragma: no-cache\r\n");
	}
	heap_string_appendf(&header, "Accept-Ranges: bytes\r\n");
	if(!keep_alive)
	{
		heap_string_appendf(&header, "Connection: close\r\n");
	} else
	{
		heap_string_appendf(&header, "Connection: Keep-Alive\r\n");
		heap_string_appendf(&header, "Keep-Alive: timeout=5, max=1000\r\n");
	}
	heap_string_appendf(&header, "\r\n");
	heap_string_appendn(&header, data, data_size);
	return header;
}

void parse_http_header_key_value_pair(const char *string, char *key, size_t keysz, char *value, size_t valuesz)
{
	int key_set = 0;
	int kn = 0;
	int vn = 0;
	for(int i = 0; string[i]; ++i)
	{
		if(string[i] == ':' && !key_set)
		{
			key_set = 1;
			continue;
		}
		
		if(!key_set)
		{
			if(kn + 1 >= keysz)
				break;
			key[kn++] = string[i];
		}
		else
		{
			if(vn + 1 >= valuesz)
				break;
			if(string[i] == ' ' && vn == 0)
				continue; //if the first character after colon is space, then skip
			value[vn++] = string[i];
		}
	}
	assert(kn < keysz);
	assert(vn < valuesz);
	key[kn] = 0;
	value[vn] = 0;
}

int parse_http_header_line(stream_t *stream, char *buf, size_t bufsz, int *overflow, size_t *index)
{
	size_t tmp_index = 0;
	if(!index)
		index = &tmp_index;
	memset(buf, 0, bufsz);
	
	if(overflow)
		*overflow = 0;
	int c;
	*index = 0;
	
	for(;;)
	{
		if(*index + 1 >= bufsz)
		{
			if(overflow)
				*overflow = 1;
			break;
		}
		c = stream_get_character(stream);
		if(c == STREAM_EOF || c == '\n')
			break;
		if(c == '\r')
		{
			if((c = stream_get_character(stream)) != '\n')
				stream_unget_character(stream, c); //unget next character, whatever that may be
			else
				break;
		}
		buf[*index] = c;
		*index += 1;
	}
	buf[*index] = '\0';
	return c == STREAM_EOF ? 1 : 0;
}

//TODO: grab method e.g POST/GET
void parse_http_header_method_and_route(stream_t *stream, heap_string *route_path)
{
	char request[8]; //can be max length of 7 + 1 for \0
	parse_ident_to_buffer(stream, request, sizeof(request), NULL);
	LOG_MESSAGE("request = %s\n", request);
	parse_whitespace(stream); //skip e.g whitespace after e.g GET/POST/PUT/DELETE/PATCH
	
	*route_path = NULL;
	parse_ident(stream, route_path); //get route_path e.g /
	LOG_MESSAGE("route_path = %s\n", route_path);
	
	parse_skip_line(stream); //don't care about HTTP/1.1
}

#define MAX_HTTP_HEADER_LENGTH (16384)
#define MAX_HTTP_HEADER_LINE_LENGTH (1024)
#define MAX_HTTP_HEADER_KEY_LENGTH (256)
#define MAX_HTTP_HEADER_VALUE_LENGTH (256)
#define MAX_HTTP_CONTENT_LENGTH (1000 * 1000 * 1000) //1GB

typedef struct
{
	char key[MAX_HTTP_HEADER_KEY_LENGTH];
	char value[MAX_HTTP_HEADER_VALUE_LENGTH];
} http_header_key_value_t;

//route_path must be freed
//kvp must be freed
int parse_http_header(
	const char *buffer,
	size_t bufsz,
	heap_string *route_path,
	struct hash_map **kvp
)
{
	assert(bufsz >= 8);
	
	stream_t stream = {
		.buffer = (char*)buffer,
		.buffer_size = bufsz,
		.buffer_index = 0
	};
	
	parse_http_header_method_and_route(&stream, route_path);
	
	*kvp = hash_map_create(http_header_key_value_t);
	char line[MAX_HTTP_HEADER_LINE_LENGTH] = {0};
	int retval = 0;
	do
	{
		if(1 == parse_http_header_line(&stream, line, sizeof(line), NULL, NULL)) //don't care about overflow so NULL
		{
			//if we hit STREAM_EOF, then the http header is longer than the bufsz we allocated for it, return HTTP 413
			retval = 0;
			break;
		}
		if(line[0] == 0) //empty line end of header
		{
			retval = stream_tell(&stream); //return end of the header position
			break;
		}
		http_header_key_value_t kv;
		parse_http_header_key_value_pair(line, kv.key, sizeof(kv.key), kv.value, sizeof(kv.value));
		hash_map_insert(*kvp, kv.key, kv);
		//printf("[%s] = [%s]\n", kv.key, kv.value);
	} while(line[0] != 0);
	return retval;
}

void send_404(int fd)
{
	heap_string header = NULL;
	const char *html_message = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>";
	int keep_alive = 0;
	header = build_http_header("text/html", 404, "Not Found", html_message, strlen(html_message), keep_alive);
	write(fd, header, heap_string_size(&header) + 1);
	heap_string_free(&header);
}

void send_http_status_code(int fd, int code, const char *msg)
{
	heap_string header = NULL;
	heap_string html_message = NULL;
	heap_string_appendf(&html_message, "HTTP Status code: %d<p>%s</p>", code, msg);
	int keep_alive = 0;
	header = build_http_header("text/html", code, msg, html_message, heap_string_size(&html_message), keep_alive);
	heap_string_free(&html_message);
	write(fd, header, heap_string_size(&header) + 1);
	heap_string_free(&header);
}

void http_response_authenticate(int fd, const char *realm)
{
	heap_string header = NULL;
	heap_string_appendf(&header, "HTTP/1.1 401 Unauthorized\r\n");
	heap_string_appendf(&header, "WWW-Authenticate: Basic realm=\"%s\"\r\n", realm);
	heap_string_appendf(&header, "Connection: close\r\n");
	heap_string_appendf(&header, "\r\n");
	write(fd, header, heap_string_size(&header) + 1);
	heap_string_free(&header);
}

void send_html(int fd, const char *html)
{
	heap_string header = NULL;
	int keep_alive = 0;
	header = build_http_header("text/html", 200, "OK", html, strlen(html), keep_alive);
	write(fd, header, heap_string_size(&header) + 1);
	heap_string_free(&header);
}

const char *http_get_header_value(struct hash_map *kvp, const char *key)
{
	http_header_key_value_t *kv = hash_map_find(kvp, key);
	if(kv)
		return kv->value;
	return "";
}

void parse_content_type(const char *string, heap_string *content_type, heap_string *charset, heap_string *boundary)
{
	*charset = NULL;
	*boundary = NULL;
	*content_type = NULL;
	
	//state
	//0 = adding character to ptr
	//1 = changing ptr based on next character
	//2 = parsing till matching = then after matching =, state gets set back to 0
	
	int state = 0;
	
	heap_string *ptr = content_type;
	
	for(int i = 0; string[i]; ++i)
	{
		if(string[i] == ' ')
			continue;
		
		switch(state)
		{
			case 1:
				switch(string[i])
				{
					case 'c':
						ptr = charset;
					break;
					
					case 'b':
						ptr = boundary;
					break;
				}
				state = 2;
			break;
			
			case 2:
				if(string[i] == '=')
					state = 0; //reset state to adding characters to ptr
			break;
			
			default:
				if(string[i] == ';')
				{
					state = 1;
				}
				else
				{
					heap_string_push(ptr, string[i]);
				}
			break;
		}
	}
}

int http_is_client_authorized(struct hash_map *kvp)
{	
	const char *authorization_value = http_get_header_value(kvp, "Authorization");
	if(*authorization_value)
	{
		//test if user/pass match
		const char *encoded = NULL;
		for(int i = 0; authorization_value[i]; ++i)
		{
			//if current character is ' ', then next is the encoded string
			//if ' ' happens to be at the end of the string
			//then i + 1 is \0, which is fine aswell, then encoded points to a empty string
			if(authorization_value[i] == ' ')
			{
				encoded = authorization_value + (i + 1);
				break;
			}
		}
		char decoded[512];
		base64_decode(decoded, sizeof(decoded), encoded);
		//printf("decoded=%s\n",decoded);
		if(!strcmp(decoded, "test:1234")) //if user:pass doesn't match
		{
			return 0;
		}
	} else
		return 1;
	return 2;
}

void serve_file(int fd, const char *path, const char *mime_type)
{
	size_t fs = 0;
	unsigned char *fb = NULL;
	
	if(!read_binary_file(path, &fb, &fs))
	{
		int keep_alive = 0;
		heap_string hdr = build_http_header(mime_type, 200, "OK", (const char*)fb, fs, keep_alive);
		int numbytes = heap_string_size(&hdr);
		int written = 0;
		while(1)
		{
			#define BUFSZ (16384)
			int bufsz = written == 0 ? numbytes : BUFSZ; //if we haven't written anything yet, just try to send the whole file in one go
			if(numbytes - written < BUFSZ)
				bufsz = numbytes - written;
			int n = write(fd, hdr + written, bufsz);
			if(n == -1 || written >= numbytes)
			{
				break;
			}
			written += n;
			//printf("sending %d/%d bytes\n", written, numbytes);
		}
        free(fb);
	}
}

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define COUNT_OF(x) (sizeof( (x) ) / sizeof( ((x)[0]) ))

static void write_buffer_to_file(const char *path, char *buffer, size_t n)
{
	if(n == 0)
		return;
	FILE *fp = fopen(path, "wb");
	if(!fp)
		return;
	fwrite(buffer, 1, n, fp);
	fclose(fp);
}

int parse_seek_string(stream_t *stream, const char *string)
{
	int i = 0;
	int n = strlen(string);
	while(1)
	{
		int c = stream_get_character(stream);
		if(c == STREAM_EOF)
			break;
		if(string[i] == c)
		{
			if(++i == n)
				return 0;
		}
		else
			i = 0;
	}
	return 1;
}

int parse_seek_character(stream_t *stream, int ch)
{
	while(1)
	{
		int c = stream_get_character(stream);
		if(c == STREAM_EOF)
			break;
		if(c == ch)
			return 0;
	}
	return 1;
}

int match_boundary(stream_t *stream, const char *boundary)
{
	for(int i = 0; boundary[i]; ++i)
	{
		int c = stream_get_character(stream);
		if(c == STREAM_EOF)
			return STREAM_EOF;
		if(c != boundary[i])
			return 1;
	}
	return 0;
}
	
typedef struct
{
	int index;
	char name[256];
	char filename[256];
	char content_type[256];
	int is_file;
	int data_index_start, data_index_end;
} form_data_t;

int parse_multipart_formdata_header_line(const char *buffer_string, form_data_t *fd)
{
	stream_t stream = {
		.buffer = (char*)buffer_string,
		.buffer_size = strlen(buffer_string) + 1,
		.buffer_index = 0
	};
	char string[MAX_HTTP_HEADER_VALUE_LENGTH];
	if(stream_read_till_character_match(&stream, string, sizeof(string), NULL, ':'))
		return 1;
	stream_skip_character(&stream, ' ');
	if(!strcmp(string, "Content-Disposition"))
	{
		if(stream_read_till_character_match(&stream, string, sizeof(string), NULL, ';'))
			return 1;
		while(1)
		{
			char key[MAX_HTTP_HEADER_KEY_LENGTH];
			char value[MAX_HTTP_HEADER_VALUE_LENGTH];
			stream_skip_character(&stream, ' ');
			if(stream_read_till_character_match(&stream, key, sizeof(key), NULL, '='))
				break;
			stream_skip_character(&stream, '"');
			if(stream_read_till_character_match(&stream, value, sizeof(value), NULL, '"'))
				break;
			if(!strcmp(key, "name"))
			{
				snprintf(fd->name, sizeof(fd->name), "%s", value);
			} else if(!strcmp(key, "filename"))
			{
				snprintf(fd->filename, sizeof(fd->filename), "%s", value);
				fd->is_file = 1;
			}
			stream_skip_character(&stream, ';');
		}
	} else if(!strcmp(string, "Content-Type"))
	{
		stream_read_till_character_match(&stream, string, sizeof(string), NULL, '\n'); //we won't match with \n, but we'll reach -1, which is the end of the string, we just want to read till end of the line, so that's fine
		snprintf(fd->content_type, sizeof(fd->content_type), "%s", string);
	}
	return 0;
}

int parse_match_and_consume_buffer(stream_t *stream, const char *buffer, size_t n)
{
	int pos = stream_tell(stream);
	for(int i = 0; i < n; ++i)
	{
		if(stream_get_character(stream) != buffer[i])
		{
			stream_seek(stream, pos, SEEK_SET); //restore position
			return 1;
		}
	}
	return 0;
}

int parse_multipart_formdata_header(stream_t *stream, const char *boundary, int boundary_length, form_data_t *fd, int *last_boundary)
{
	char line[MAX_HTTP_HEADER_LINE_LENGTH] = {0};
	while(1)
	{
		size_t line_length;
		int overflow;
		if(parse_http_header_line(stream, line, sizeof(line), &overflow, &line_length))
		{
			return 1;
		}
		if(line[0] == 0)
		{
			break;
		}
		if(parse_multipart_formdata_header_line(line, fd))
		{
			return 1;
		}
	}
	fd->data_index_start = stream_tell(stream);
	while(1)
	{
		//scan till next \r\n
		int ch = stream_get_character(stream);
		int pos = stream_tell(stream);
		if(ch == STREAM_EOF)
		{
			fd->data_index_end = pos - 1;
			return 1;
		}
		if(ch == '\r')
		{
			if(!parse_match_and_consume_buffer(stream, "\n--", 3)
				&&
				!parse_match_and_consume_buffer(stream, boundary, boundary_length))
			{
				fd->data_index_end = pos - 1;
				if(!parse_match_and_consume_buffer(stream, "--", 2))
				{
					*last_boundary = 1;
				}
				if(parse_seek_character(stream, '\n'))
					return 1;
				break;
			}
		}
	}
	return 0;
}

int parse_multipart_formdata(stream_t *stream, const char *content_type_boundary, form_data_t *form_data, size_t max_form_data_entries, size_t *num_form_data_entries)
{
	if(parse_seek_character(stream, '-'))
		return 1;
	if(parse_seek_character(stream, '\n'))
		return 1;
	*num_form_data_entries = 0;
	form_data_t *fd = &form_data[*num_form_data_entries];
	*num_form_data_entries += 1;
	memset(fd, 0, sizeof(form_data_t));
	int last_boundary = 0;
	int content_type_boundary_length = strlen(content_type_boundary);
	do
	{
		if(parse_multipart_formdata_header(stream, content_type_boundary, content_type_boundary_length, fd, &last_boundary))
			return 1;
		if(*num_form_data_entries >= max_form_data_entries)
			return 1;
		//printf("fd name = %s, is_file=%d, filename=%s,content_type=%s,data_size=%d\n",fd->name,fd->is_file,fd->filename,fd->content_type,fd->data_index_end - fd->data_index_start);
		fd = &form_data[*num_form_data_entries];
		fd->index = *num_form_data_entries + 1;
		*num_form_data_entries += 1;
	} while(!last_boundary);
	return 0;
}

void parse_content(int fd, int *http_status, int content_length, struct hash_map *kvp, const char *header_data, size_t bytesread)
{
	if(content_length <= 0)
		return;

	if(content_length > MAX_HTTP_CONTENT_LENGTH)
	{
		*http_status = 413;
		return;
	}
	
	const char *content_type_string = http_get_header_value(kvp, "Content-Type");
	
	heap_string boundary;
	heap_string charset;
	heap_string content_type;
	
	printf("content_length=%d\n",content_length);
	assert(bytesread <= content_length);
	//as of now the max body length is 1GB, just read that into memory and parse it
	char *data = malloc(content_length);
	//copy the first bit of data in the header over
	memcpy(data, header_data, bytesread);
	char temp_buf[16384];
	while(bytesread < content_length)
	{
		int n = recv(fd, temp_buf, sizeof(temp_buf), 0);
		if(n == 0 || n == -1)
		{
			*http_status = 400;
			break;
		}
		memcpy(data + bytesread, temp_buf, MIN(n, sizeof(temp_buf)));
		bytesread += n;
	}
	
	if(*content_type_string && *http_status == 200)
	{
		parse_content_type(content_type_string, &content_type, &charset, &boundary);
		printf("content_type=%s,charset=%s,boundary=%s\n",content_type,charset,boundary);
		
		if(!strcmp(content_type, "multipart/form-data"))
		{
			printf("got %lu bytes!! multipart/form-data\n", bytesread);
			
			form_data_t form_data[16]; //TODO: increase max form_data
			stream_t stream = {
				.buffer = (char*)data,
				.buffer_size = bytesread,
				.buffer_index = 0
			};
			
			size_t num_entries = 0;
			parse_multipart_formdata(&stream, boundary, form_data, COUNT_OF(form_data), &num_entries);
			if(uploads_enabled)
			{
				for(int i = 0; i < num_entries; ++i)
				{
					form_data_t *fd = &form_data[i];
					printf("fd name = %s, is_file=%d, filename=%s,content_type=%s,data_size=%d,start=%d,end=%d\n",fd->name,fd->is_file,fd->filename,fd->content_type,fd->data_index_end - fd->data_index_start,fd->data_index_start,fd->data_index_end);
					if(!form_data[i].is_file)
						continue;
					char filename[512];
					//TODO: FIX this is unsafe...
					snprintf(filename, sizeof(filename), "uploads/%s", form_data[i].filename);
					printf("writing %s, %d bytes\n", filename, form_data[i].data_index_end - form_data[i].data_index_start);
					if(form_data[i].data_index_end > form_data[i].data_index_start)
						write_buffer_to_file(filename, data + form_data[i].data_index_start, form_data[i].data_index_end - form_data[i].data_index_start);
				}
			}
		} else
		{
			*http_status = 415;
		}
	}
	//write_buffer_to_file("data.bin", data, bytesread);
	free(data);
	
	heap_string_free(&boundary);
	heap_string_free(&charset);
	heap_string_free(&content_type);
}

void handle_client(int fd)
{
	char buf[MAX_HTTP_HEADER_LENGTH]={0};
	int n = recv(fd, buf, sizeof(buf), 0);//MSG_DONTWAIT);
	if(n == 0)
	{
		//disconnected
		LOG_MESSAGE("erasing node\n");
	} else if(n == -1)
	{
		//if(errno != EWOULDBLOCK)
			//perror("recv");
	} else
	{
		LOG_MESSAGE("%d bytes\n", n);
		//printf("%s\n", buf);
		if(n >= 8)
		{
			heap_string route_path;
			struct hash_map *kvp;
			int data_pos = parse_http_header(buf, sizeof(buf), &route_path, &kvp);
			//if there's no content-length, then data_pos should just be ignored
			if(data_pos == 0)
			{
				send_http_status_code(fd, 400, "Bad Request");
				//send_http_status_code(fd, 418, "I'm a teapot");
			} else
			{
				int auth_result = http_is_client_authorized(kvp);
				if(auth_result == 1)
				{
					http_response_authenticate(fd, "Test realm");
				} else if(auth_result == 2)
				{
					send_http_status_code(fd, 401, "Unauthorized");
				} else
				{
					int content_length = atoi(http_get_header_value(kvp, "Content-Length"));
					int http_status = 200;
					parse_content(fd, &http_status, content_length, kvp, buf + data_pos, MIN(sizeof(buf) - data_pos, content_length));
					if(http_status == 200)
					{
						if(!strcmp(route_path, "/favicon.ico"))
						{
							send_404(fd);
						} else if(!strcmp(route_path, "/test.jpg"))
						{
							serve_file(fd, "test.jpg", "image/jpeg");
						} else
						{
							const char *html = "<img src='test.jpg'><marquee>TEST</marquee><form enctype='multipart/form-data' method='post' action='/'><input type='text' name='text'><input type='file' name='file'><input type='text' name='textfield'><textarea name='textarea'></textarea><input type='submit' name='submit' value='upload'></form>";
							send_html(fd, html);
						}
					} else
					{
						switch(http_status)
						{
							case 413:
								send_http_status_code(fd, http_status, "Payload Too Large");
							break;
							
							case 415:
								send_http_status_code(fd, http_status, "Unsupported Media Type");
							break;
							
							default:
								send_http_status_code(fd, http_status, "Something went wrong.");
							break;
						}
					}
				}
			}
			
			hash_map_destroy(&kvp);
			#if 0
			struct route *route = get_route(route_path);
			if(route == NULL || route->callback(route, fd, route->file) == 1)
				write(fd, hdr_404, heap_string_size(&hdr_404) + 1);
			#endif
			
			heap_string_free(&route_path);
		} else
			send_404(fd);
	}
}

int main(void)
{
	struct stat st;
	if(stat("uploads", &st) == 0 && st.st_mode & S_IFDIR)
	{
		uploads_enabled = 1;
	}
	#ifdef _WIN32
	static WSADATA wsa_data;
	if(WSAStartup(MAKEWORD(2,0), &wsa_data) != 0)
		return 0;
	#endif
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	
	int port = 8000;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = 0;
	sa.sin_port = htons(port);
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock == -1)
		perror("socket");
	int const_value_1 = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&const_value_1, sizeof(int));
	
	if(bind(sock, (struct sockaddr*)&sa, sizeof(sa)) == -1)
		perror("bind");
	
	if(listen(sock, 0) == -1)
		perror("listen");
	signal(SIGINT, stop_server);
	while(listening)
	{
		/*
		fd_set set;
		struct timeval timeout;
		int rv;
		FD_ZERO(&set);
		FD_SET(sock, &set);
		
		timeout.tv_sec = 20;
		timeout.tv_usec = 0;
		repeat:
		
		rv = select(sock + 1, &set, NULL, NULL, NULL);
		if(rv == -1)
		{
			perror("rv");
			break;
		} else if(rv == 0)
		{
			LOG_MESSAGE("timeout...\n");
			goto repeat;
		}
		*/
		
		struct sockaddr_in client_sa;
		int client_fd = accept(sock, (struct sockaddr*)&client_sa, &(socklen_t){sizeof(client_sa)});
		if(client_fd == -1)
		{
			if(errno != EWOULDBLOCK)
			{
				perror("client error");
			}
		} else
		{
			handle_client(client_fd);
			#ifdef _WIN32
			shutdown(client_fd, SD_SEND);
			closesocket(client_fd);
			#else
			shutdown(client_fd, SHUT_WR);
			close(client_fd);
			#endif
		}
	}
	return 0;
}

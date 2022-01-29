#define memory_allocate malloc
#define memory_deallocate free

#define HEAP_STRING_IMPL
#include "heap_string.h"

#define LINKED_LIST_IMPL
#include "linked_list.h"

#define HASH_MAP_IMPL
#include "hash_map.h"

#define PARSE_IMPL
#include "parse.h"

#include <signal.h>
#include <time.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include "base64.h"

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

struct client
{
	struct sockaddr_in sa;
	int fd;
};

struct linked_list *clients = NULL;

int set_non_blocking(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

void on_client_disconnect(struct client *c)
{
	shutdown(c->fd, SHUT_RDWR);
	close(c->fd);
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

struct route
{
	int (*callback)(struct route*, int, const char*);
	const char *file;
	//cached buffer not being freed at the moment.. memleaks
	heap_string cached_buffer;
};

int route_serve_file(struct route *route, int fd, const char *file)
{
	if(route->cached_buffer != NULL)
	{
		write(fd, route->cached_buffer, heap_string_size(&route->cached_buffer) + 1);
		return 0;
	}
	if(!file)
		return 1;
	if(file[0] == '/')
		return 1;
	if(strstr(file, ".."))
		return 1;
	
	size_t fs = 0;
	unsigned char *fb = NULL;
	
	if(read_text_file(file, &fb, &fs))
		return 1;
	int keep_alive = 0;
	heap_string hdr = build_http_header("text/html", 200, "OK", fb, fs, keep_alive);
	free(fb);
	write(fd, hdr, heap_string_size(&hdr) + 1);
	//heap_string_free(&hdr);
	route->cached_buffer = hdr;
	return 0;
}

struct hash_map *routes = NULL;

void register_route(const char *route_path, int (*callback)(struct route*, int, const char*), const char *file)
{
	struct route r;
	r.callback = callback;
	r.file = file;
	r.cached_buffer = NULL;
	hash_map_insert(routes, route_path, r);
}

void setup_routes()
{
	routes = hash_map_create(struct route);
	
	char test[128];
	for(int i = 0; i < 100000; ++i)
	{
		sprintf(test, "/test%d", i);
		register_route(test, route_serve_file, "index.html");
	}
}

struct route *get_route(const char *route_path)
{
	return (struct route*)hash_map_find(routes, route_path);
}

void destroy_routes()
{
	hash_map_destroy(&routes);
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

int parse_http_header_line(FILE *fp, char *buf, size_t bufsz, int *overflow)
{
	if(overflow)
		*overflow = 0;
	int c;
	size_t index = 0;
	
	for(;;)
	{
		if(index + 1 >= bufsz)
		{
			if(overflow)
				*overflow = 1;
			break;
		}
		c = fgetc(fp);
		if(c == EOF || c == '\n')
			break;
		if(c == '\r')
		{
			if((c = fgetc(fp)) != '\n')
				ungetc(c, fp); //unget next character, whatever that may be
			else
				break;
		}
		buf[index++] = c;
	}
	buf[index] = '\0';
	return c == EOF ? 1 : 0;
}

//TODO: grab method e.g POST/GET
void parse_http_header_method_and_route(FILE *stream, heap_string *route_path)
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
	FILE *stream = fmemopen((void*)buffer, bufsz, "r");
	
	parse_http_header_method_and_route(stream, route_path);
	
	*kvp = hash_map_create(http_header_key_value_t);
	char line[MAX_HTTP_HEADER_LINE_LENGTH] = {0};
	do
	{
		if(1 == parse_http_header_line(stream, line, sizeof(line), NULL)) //don't care about overflow so NULL
		{
			//if we hit EOF, then the http header is longer than the bufsz we allocated for it, return HTTP 413
			return 0;
		}
		if(line[0] == 0) //empty line end of header
		{
			return ftell(stream); //return end of the header position
		}
		http_header_key_value_t kv;
		parse_http_header_key_value_pair(line, kv.key, sizeof(kv.key), kv.value, sizeof(kv.value));
		hash_map_insert(*kvp, kv.key, kv);
		//printf("[%s] = [%s]\n", kv.key, kv.value);
	} while(line[0] != 0);
	return 0;
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
		printf("decoded=%s\n",decoded);
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
		heap_string hdr = build_http_header(mime_type, 200, "OK", fb, fs, keep_alive);
		int numbytes = heap_string_size(&hdr);
		int written = 0;
		while(1)
		{
			#define BUFSZ (16384)
			int bufsz = BUFSZ;
			if(numbytes - written < BUFSZ)
				bufsz = numbytes - written;
			int n = write(fd, hdr + written, bufsz);
			if(n == -1 || written >= numbytes)
			{
				break;
			}
			written += n;
			printf("sending %d/%d bytes\n", written, numbytes);
		}
		free(fb);
	}
}

void handle_client(int fd)
{
	char buf[MAX_HTTP_HEADER_LENGTH]={0};
	int n = recv(fd, buf, sizeof(buf), 0);//MSG_DONTWAIT);
	if(n == 0)
	{
		//disconnected
		LOG_MESSAGE("erasing node\n");
		//linked_list_erase_node(clients, node);
	} else if(n == -1)
	{
		if(errno != EWOULDBLOCK)
			perror("recv");
	} else
	{
		LOG_MESSAGE("%d bytes\n", n);
		printf("%s\n", buf);
		FILE *stream = NULL;
		if(n >= 8)
		{
			heap_string route_path;
			struct hash_map *kvp;
			int data_pos = parse_http_header(buf, sizeof(buf), &route_path, &kvp);
			printf("data_pos=%d\n",data_pos);
			printf("data=<%s>\n", buf + data_pos);
			int content_length = atoi(http_get_header_value(kvp, "Content-Length"));
			const char *content_type_string = http_get_header_value(kvp, "Content-Type");
			
			heap_string boundary;
			heap_string charset;
			heap_string content_type;
			
			if(*content_type_string)
			{
				parse_content_type(content_type_string, &content_type, &charset, &boundary);
				printf("content_type=%s,charset=%s,boundary=%s\n",content_type,charset,boundary);
			}
			
			heap_string_free(&boundary);
			heap_string_free(&charset);
			heap_string_free(&content_type);
			
			//if there's no content-length, then data_pos should just be ignored
			if(data_pos == 0)
			{
				send_http_status_code(fd, 413, "Payload Too Large");
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
					if(!strcmp(route_path, "/favicon.ico"))
					{
						send_404(fd);
					} else if(!strcmp(route_path, "/test.jpg"))
					{
						serve_file(fd, "test.jpg", "image/jpeg");
					} else if(!strcmp(route_path, "/test.zip"))
					{
						serve_file(fd, "test.zip", "application/zip");
					} else
					{
						const char *html = "<img src='test.jpg' style='width:100px;height:100px;'><marquee>TEST</marquee><form enctype='multipart/form-data' method='post' action='/'><input type='text' name='text'><input type='file' name='file'><input type='submit' name='submit' value='upload'></form>";
						send_html(fd, html);
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
	setup_routes();
	
	clients = linked_list_create(struct client);
	linked_list_set_node_value_finalizer(clients, (linked_list_node_finalizer_callback_t)on_client_disconnect);
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	
	int port = 8000;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = 0;
	sa.sin_port = htons(port);
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock == -1)
		perror("socket");
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	
	//if(set_non_blocking(sock) == -1)
		//perror("failed to set non-blocking");
	
	if(bind(sock, (struct sockaddr*)&sa, sizeof(sa)) == -1)
		perror("bind");
	
	if(listen(sock, 0) == -1)
		perror("listen");
	signal(SIGINT, stop_server);
	while(listening)
	{
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
		
		struct client cl;
		cl.fd = accept(sock, (struct sockaddr*)&cl.sa, &(socklen_t){sizeof(cl.sa)});
		if(cl.fd == -1)
		{
			if(errno != EWOULDBLOCK)
			{
				perror("client error");
			}
		} else
		{
			//if(-1 == set_non_blocking(cl.fd))
				//perror("failed to set non-blocking for client");
			//new client...
			//linked_list_prepend(clients, cl);
			LOG_MESSAGE("client\n");
			printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
			handle_client(cl.fd);
			printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
			shutdown(cl.fd, SHUT_WR);
			close(cl.fd);
		}
		#if 0
		//loop through the clients
		linked_list_foreach_node(clients, node,
		{
			struct client* it = linked_list_node_value(node);
		});
		#endif
	}
	linked_list_destroy(&clients);
	destroy_routes();
	return 0;
}
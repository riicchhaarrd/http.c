#define memory_allocate malloc
#define memory_deallocate free

#define HEAP_STRING_IMPL
#include "../heap_string.h"

#define LINKED_LIST_IMPL
#include "../linked_list.h"

#define HASH_MAP_IMPL
#include "../hash_map.h"

#define PARSE_IMPL
#include "../parse.h"

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

heap_string build_http_header(const char *content_type, const char *data, size_t data_size)
{
	heap_string header = NULL;
	heap_string_appendf(&header, "HTTP/1.1 200 OK\r\n");
	heap_string_appendf(&header, "Content-Type: %s; charset=UTF-8\r\n", content_type);
	heap_string_appendf(&header, "Content-Length: %d\r\n", data_size + 1);
	heap_string_appendf(&header, "Referrer-Policy: no-referrer\r\n");
	heap_string_appendf(&header, "Server: http.c\r\n");
	
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char s[64];
    assert(strftime(s, sizeof(s), "%c", tm));
	heap_string_appendf(&header, "Date: %s\r\n", s);
	
	int caching = 0;
	
	if(!caching)
	{
		heap_string_appendf(&header, "Cache-control: no-cache\r\n");
		heap_string_appendf(&header, "Pragma: no-cache\r\n");
	}
	heap_string_appendf(&header, "Accept-Ranges: bytes\r\n");
	heap_string_appendf(&header, "Connection: close\r\n");
	heap_string_appendf(&header, "\r\n\r\n");
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
	heap_string hdr = build_http_header("text/html", fb, fs);
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

int main(void)
{
	setup_routes();
	
	//build 404 page

	static const char message_404[] = "404";
	heap_string hdr_404 = build_http_header("text/plain", message_404, sizeof(message_404));
	
	clients = linked_list_create(struct client);
	linked_list_set_node_value_finalizer(clients, on_client_disconnect);
	
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
	
	if(set_non_blocking(sock) == -1)
		perror("failed to set non-blocking");
	
	if(bind(sock, (struct sockaddr*)&sa, sizeof(sa)) == -1)
		perror("bind");
	
	if(listen(sock, 5) == -1)
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
			if(-1 == set_non_blocking(cl.fd))
				perror("failed to set non-blocking for client");
			//new client...
			linked_list_prepend(clients, cl);
			LOG_MESSAGE("client\n");
		}
		
		//loop through the clients
		linked_list_foreach_node(clients, node,
		{
			struct client* it = linked_list_node_value(node);
			
			char buf[1024];
			//LOG_MESSAGE("it = %d\n", it);
			int n = recv(it->fd, buf, sizeof(buf), MSG_DONTWAIT);
			if(n == 0)
			{
				//disconnected
				LOG_MESSAGE("erasing node\n");
				linked_list_erase_node(clients, node);
				break;
			} else if(n == -1)
			{
				if(errno != EWOULDBLOCK)
					perror("recv");
			} else
			{
				LOG_MESSAGE("%d bytes\n", n);
				printf("-------%s\n", buf);
				FILE *stream = NULL;
				if(n >= 8 && (stream = fmemopen(buf, sizeof(buf), "r")))
				{
					char request[8]; //can be max length of 7 + 1 for \0
					parse_ident_to_buffer(stream, request, sizeof(request), NULL);
					LOG_MESSAGE("request = %s\n", request);
					parse_whitespace(stream);
					
					heap_string route_path = NULL;
					parse_ident(stream, &route_path);
					LOG_MESSAGE("route_path = %s\n", route_path);
					
					struct route *route = get_route(route_path);
					if(route == NULL || route->callback(route, it->fd, route->file) == 1)
						write(it->fd, hdr_404, heap_string_size(&hdr_404) + 1);
					
					heap_string_free(&route_path);
				} else
					write(it->fd, hdr_404, heap_string_size(&hdr_404) + 1);
			}
		});
	}
	heap_string_free(&hdr_404);
	linked_list_destroy(&clients);
	destroy_routes();
	return 0;
}
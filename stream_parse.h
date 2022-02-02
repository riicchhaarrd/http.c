#ifndef STREAM_PARSE_H
#define STREAM_PARSE_H

#include <stdio.h> //FILE
#include <stdlib.h> //atof
#include <ctype.h> //isspace
//should probably make heap_string a struct and forward declare it in the func prototype below
#include "heap_string.h"

typedef struct
{
	char *buffer;
	size_t buffer_size;
	size_t buffer_index;
} stream_t;

#ifndef STREAM_PARSE_IMPL
void parse_whitespace(stream_t*);
void parse_skip_line(stream_t*);
int parse_float(stream_t*, float* out);
int parse_float3(stream_t*, float *v);
/* don't forget to free ident! */
int parse_ident(stream_t*, heap_string *ident);
int parse_character(stream_t*, int ch);
int parse_characters(stream_t*, const char *str);
int parse_ident_to_buffer(stream_t*, char *buf, size_t bufsz, int *overflow);

int stream_tell(stream_t*);
int stream_peek_character(stream_t*);
void stream_unget_character(stream_t*, int ch);
int stream_get_character(stream_t*);
int stream_seek_character(stream_t*, int character);
void stream_skip_character(stream_t*, int character);
int stream_read_till_character_match(stream_t*, char *out, size_t outsize, size_t *outcount, int character);
int stream_seek_string(stream_t*, const char *string);
void stream_seek(stream_t*, int pos, int);

int fpeekc(FILE*);
#else
int fpeekc(FILE *fp)
{
    int c = fgetc(fp);
    ungetc(c, fp);
    return c;
}

int stream_get_character(stream_t *stream)
{
	if(stream->buffer_index + 1 >= stream->buffer_size)
		return EOF;
	return stream->buffer[stream->buffer_index++];
}

int stream_seek_character(stream_t *stream, int character)
{
	int ch;
	while(1)
	{
		ch = stream_get_character(stream);
		if(ch == EOF || ch == character)
			break;
	}
	return ch == character ? 0 : 1;
}

void stream_skip_character(stream_t *stream, int character)
{
	while(1)
	{
		int ch = stream_get_character(stream);
		if(ch == EOF || ch == character)
			break;
	}
}

int stream_read_till_character_match(stream_t *stream, char *out, size_t outsize, size_t *outcount, int character)
{
	size_t tmp_count;
	if(!outcount)
		outcount = &tmp_count;
	*outcount = 0;
	int ch;
	while(1)
	{
		ch = stream_get_character(stream);
		if(ch == EOF || ch == character)
			break;
		if(*outcount + 1 >= outsize)
			return 1;
		out[*outcount] = ch;
		*outcount += 1;
	}
	out[*outcount] = 0;
	return ch == character ? 0 : 1;
}

int stream_seek_string(stream_t *stream, const char *string)
{
	int n = 0;
	int string_length = strlen(string);
	while(1)
	{
		int ch = stream_get_character(stream);
		if(ch == EOF)
			break;
		
		if(n >= string_length)
			break; //shouldn't happen really.. like ever
		
		if(string[n] == ch)
		{
			++n;
			if(n == string_length)
				return 0;
		} else
			n = 0;
	}
	return 1;
}

int stream_tell(stream_t *stream)
{
	return stream->buffer_index;
}

void stream_seek(stream_t *stream, int pos, int unused)
{
	stream->buffer_index = pos;
}

int stream_peek_character(stream_t *stream)
{
	if(stream->buffer_index >= stream->buffer_size)
		return EOF;
	return stream->buffer[stream->buffer_index];
}

void stream_unget_character(stream_t *stream, int ch)
{
	if(stream->buffer_index > 0)
		--stream->buffer_index;
}

void parse_whitespace(stream_t *stream)
{
	while(1)
	{
		int pk = stream_peek_character(stream);
		if(pk == EOF)
			return;
		if(pk != ' ' && pk != '\t')
			return;
		stream_get_character(stream);
	}
}

void parse_skip_line(stream_t *stream)
{
	int c;
	do
	{
		c = stream_get_character(stream);
	} while(c != EOF && c != '\n');
}

int parse_float(stream_t *stream, float* out)
{
	int c;
	char string[128]; //let's just allow up to 128..
	size_t stringindex = 0;
	do
	{
		if(stringindex >= sizeof(string))
			return 1;
		c = stream_get_character(stream);
		string[stringindex++ % sizeof(string)] = c;
	} while(c != EOF && ( c == 'e' || isdigit(c) || c == '-' || c == '.' ));
	*out = (float)atof(string);
	stream_unget_character(stream, c); //we've parsed 1 too many
	return c == EOF ? 1 : 0;
}

int parse_float3(stream_t *stream, float *v)
{
	parse_whitespace(stream);
	if(parse_float(stream, &v[0]))
		return 1;
	parse_whitespace(stream);
	if(parse_float(stream, &v[1]))
		return 1;
	parse_whitespace(stream);
	if(parse_float(stream, &v[2]))
		return 1;
	parse_whitespace(stream);
	return 0;
}

int parse_ident_to_buffer(stream_t *stream, char *buf, size_t bufsz, int *overflow)
{
	if(overflow)
		*overflow = 0;
	parse_whitespace(stream);
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
		c = stream_get_character(stream);
		if(c == EOF || isspace(c))
		{
			stream_unget_character(stream, c); //unget space
			break;
		}
		buf[index++] = c;
	}
	buf[index] = '\0';
	return c == EOF ? 1 : 0;
}

/* don't forget to free ident! */

int parse_ident(stream_t *stream, heap_string *ident)
{
	parse_whitespace(stream);
	int c;
	for(;;)
	{
		c = stream_get_character(stream);
		if(c == EOF || isspace(c))
		{
			stream_unget_character(stream, c); //unget space
			break;
		}
		heap_string_push(ident, c);
	}
	if(c == EOF)
		heap_string_free(ident);
	return c == EOF ? 1 : 0;
}

int parse_character(stream_t *stream, int ch)
{
	parse_whitespace(stream);
	if(stream_peek_character(stream) != ch)
	{
		printf("expected %c got %c at %d\n", ch, stream_peek_character(stream), stream_tell(stream));
		return 1;
	}
	stream_get_character(stream);
	parse_whitespace(stream);
	return 0;
}

int parse_characters(stream_t *stream, const char *str)
{
	size_t len = strlen(str);
	for(size_t i = 0; i < len; ++i)
	{
		if(parse_character(stream, str[i]))
			return 1;
	}
	return 0;
}
#endif
#endif
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef unsigned char u8;

static const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_lookup_character(int ch)
{
    if(ch == '=')
        return 0;
    for(int i = 0; base64_table[i]; ++i)
    {
        if(base64_table[i] == ch)
            return i;
    }
    return -1;
}

static void base64_decode(char *out, size_t outsz, const char *encoded)
{
    int len = strlen(encoded);
    int numbits = len * 6; //each character corresponds to max 6 bits when looked up in the table
    int bitcount = 0;
    int charindex, bitindex;
    u8 byte = 0;
    int n = 0;
    int byteindex = 0;
    while(1)
    {
        charindex = bitcount / 6;
        if(bitcount >= numbits)
            break;
        bitindex = bitcount % 6;
        u8 ch = base64_lookup_character(encoded[charindex]);
	int bit = (ch & (1 << (6 - bitindex - 1))) != 0;
        byte |= (bit << (8 - byteindex - 1));
        ++byteindex;
        if(byteindex == 8)
        {
            if(n + 1 >= outsz)
                break;
            out[n++] = byte;
            byteindex = 0;
            byte = 0;
        }
        ++bitcount;
    }
    out[n] = 0;
}
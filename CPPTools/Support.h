#pragma once

#ifndef _SUPPORT_H
#define _SUPPORT_H

#include "ArchAbstract.h"

#include "Crypto.h"


namespace Tools {
	char* strappend(char*, char*);
	char* strappend(char*, const char*);
	char* strappend(const char*, char*);
	char* strappend(const char*, const char*);
	void destructivePrint(char* message, ulong_64b size);
	void destructivePrint(char* message);
	void destructivePrintln(char* message, ulong_64b size);
	void destructivePrintln(char* message);
	ulong_64b indexOf(char*, char);
	ulong_64b lastIndexOf(char*, char);
	char* copydata(const char*, ulong_64b);
	char* toHexString(const void* data, ulong_64b size, bool);
	char* toHexString(const void* data, ulong_64b size);
	char* toHexString(ulong_64b);
	void* parseHex(char*, size_t *rSize);
	ulong_64b parseHexLong(char*);
	bool isDigit(char c);
	bool isNumber(char* c);
	bool isIP(char* c);
}

#endif
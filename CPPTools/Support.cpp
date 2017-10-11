#include <iostream>
#include <memory>

#include "Support.h"

namespace Tools {
	char* strappend(char* to, char* from) {
		ulong_64b l, l1;
		to = (char*)realloc(to, (l = strlen(to)) + (l1 = strlen(from))+1);
		memcpy(to + l, from, l1);
		to[l + l1] = 0;
		return to;
	}

	char* strappend(char* to, const char* from) {
		ulong_64b l, l1;
		to = (char*)realloc(to, (l = strlen(to)) + (l1 = strlen(from))+1);
		memcpy(to + l, from, l1);
		to[l + l1] = 0;
		return to;
	}

	char* strappend(const char* from, char* to) {
		ulong_64b l, l1;
		to = (char*)realloc(to, (l = strlen(to)) + (l1 = strlen(from))+1);
		memcpy(to + l1, to, l);
		memcpy(to, from, l1);
		to[l + l1] = 0;
		return to;
	}

	char* __cdecl strappend(const char* from, const char* from1) {
		ulong_64b l, l1;
		char* to = (char*)malloc((l = strlen(from)) + (l1 = strlen(from1))+1);
		memcpy(to, from, l);
		memcpy(to + l, from1, l1);
		to[l + l1] = 0;
		return to;
	}

	void destructivePrint(char* message, ulong_64b size) {
		for (ulong_64b t = 0; t < size; ++t) std::cout << message[t];
		free(message);
	}

	void destructivePrint(char* message) {
		std::cout << message;
		free(message);
	}

	void destructivePrintln(char* message, ulong_64b size) {
		destructivePrint(message, size);
		std::cout << std::endl;
	}

	void destructivePrintln(char* message) {
		destructivePrint(message);
		std::cout << std::endl;
	}

	ulong_64b indexOf(char* in, char find) {
		ulong_64b t = strlen(in);
		for (ulong_64b t1 = 0; t1 < t; ++t1) if (in[t1] == find) return t1;
		return -1;
	}

	ulong_64b lastIndexOf(char* in, char find) {
		ulong_64b t = strlen(in);
		for (ulong_64b t1 = 0; t1 < t; ++t1) if (in[t - t1 - 1] == find) return t - t1;
		return -1;
	}

	char* copydata(const char* from, ulong_64b readBytes) {
		char* c = (char*)malloc(readBytes);
		memcpy(c, from, readBytes);
		return c;
	}

	char* toHexString(const void* data, ulong_64b size, bool ignorePreZero) {
		char* c = (char*)data;

		ulong_64b lastNonZero = ignorePreZero?0:size-1;
		if (ignorePreZero) {
			for (ulong_64b t = size; t > 0; --t)
				if (c[t - 1] != 0) {
					lastNonZero = t - 1;
					goto Ayy;
				}
		}
		else goto Ayy;
		return new char[2]{ '0', 0 };

		Ayy:
		char* c1 = (char*)new char[1 + ((lastNonZero + 1) * 2)];
		c1[lastNonZero * 2] = 0;
		for (ulong_64b j = lastNonZero + 1; j > 0; --j) {
			ulong_64b t = 1 + lastNonZero - j;
			c1[2 * t] = (c[j - 1] >> 4) & 15;
			if (c1[(2 * t)] < 10) c1[(2 * t)] += 48;
			else c1[(2 * t)] += 55;

			c1[(2 * t) + 1] = (c[j - 1]) & 15;
			if (c1[(2 * t) + 1] < 10) c1[(2 * t) + 1] += 48;
			else c1[(2 * t) + 1] += 55;
		}
		return c1;
	}

	char* toHexString(const void* data, ulong_64b size) { return toHexString(data, size, true); }

	char* toHexString(ulong_64b value) { return toHexString(&value, sizeof(value), false); }

	void* parseHex(char* c, size_t *rSize) {
		size_t len = strlen(c);
		size_t rem = (len % 2);
		size_t target = (len + rem) / 2;
		if (rSize != nullptr) *rSize = target;
		char* out = new char[target];
		if (rem) out[target - 1] = c[0] - (c[0]>64 ? 55 : 48);
		for (size_t t = rem; t < len; ++t) {
			out[target - 1 - ((t + rem) / 2)] |= (c[t] - (c[t] > 64 ? 55 : 48)) << (((t + 1) % 2) * 4);
		}
		return out;
	}

	ulong_64b parseHexLong(char* c) { return *(ulong_64b*)parseHex(c, nullptr); }

	bool isDigit(char c) { return (c > 47) && (c < 58); }

	bool isIP(char* c) {
		size_t t = strlen(c);
		size_t count = 0;
		for (size_t t1 = 0; t1 < t; ++t1) {
			if (c[t1] == '.') {
				if ((t1 + 1) == t) return false;
				++count;
			}
			else if (!isDigit(c[t1])) return false;
			if (count > 3) return false;
		}
		return count == 3;
	}

	bool isNumber(char* c) {
		for (size_t t = strlen(c); t > 0; --t) if (!isDigit(c[t - 1])) return false;
		return true;
	}
}

#include "include/sm3.h"
#include <time.h>

#define LARGE_BUFFER_SIZE (500 * 1024 * 1024) // 500 MB
uint8_t g_in[LARGE_BUFFER_SIZE] = { 0 };

void sm3_self_check()
{
	uint8_t msg[100] = { 0 };
	uint8_t digest[32] = { 0 };
	uint8_t expected_digest[32] =
	{
		0x4B, 0x28, 0x33, 0xC1, 0x58, 0xDD, 0x41, 0x61, 0x4B, 0x76, 0xE3, 0x7F, 0x18, 0x88, 0x92, 0x43,
		0xBD, 0x6B, 0x4A, 0x74, 0x4E, 0x36, 0xDE, 0x60, 0x92, 0x0A, 0x2F, 0x89, 0xE4, 0x09, 0xC6, 0x4E,
	};
	size_t i = 0;
	size_t msg_len = 100;

	for (i = 0; i < msg_len; ++i)
	{
		msg[i] = i;
	}

	sm3(msg, msg_len, digest);

	if (memcmp(digest, expected_digest, 32) != 0)
	{
		puts("Digest and expected is not equal!");
		return;
	}

	puts("SM3 selft test pass!");
	puts("\n");
}

void sm3_hmac_self_check() {
    // test1
    u1 data1[] = "777";
    u1 key1[] = "key";
    u1 expected_mac1[32] = {0x44, 0xf4, 0xd3, 0xac, 0x9b, 0x13, 0xbb, 0x75, 0xc3, 0x01, 0x2b, 0x87, 0x5b, 0x8a, 0x64, 0xe1, 0x69, 0x43, 0x88, 0x55, 0xed, 0x7e, 0x5a, 0x1b, 0x09, 0x78, 0x8f, 0x79, 0x4d, 0x1b, 0xa7, 0x7a};

    u1 mac1[32];
    sm3_hmac(data1, strlen((char *)data1), key1, strlen((char *)key1), mac1);

    if (memcmp(mac1, expected_mac1, 32) == 0) {
        printf("Test 1 Passed: Correct MAC\n");
    } else {
        printf("Test 1 Failed: Incorrect MAC\n");
    }

    // test2 empty input.
    u1 data2[] = "";
    u1 key2[] = "EmptyKey";
    u1 expected_mac2[32] = {0x35, 0x72, 0x87, 0xc7, 0x2c, 0x2a, 0xcf, 0x27, 0x97, 0x97, 0x8b, 0x0a, 0x8f, 0x73, 0xb1, 0x65, 0xbb, 0xed, 0xee, 0x3c, 0x9d, 0x99, 0x45, 0xcb, 0x19, 0x3c, 0xac, 0xef, 0x19, 0x20, 0x85, 0x5c};

    u1 mac2[32];
    sm3_hmac(data2, strlen((char *)data2), key2, strlen((char *)key2), mac2);

    if (memcmp(mac2, expected_mac2, 32) == 0) {
        printf("Test 2 Passed: Correct MAC\n");
    } else {
        printf("Test 2 Failed: Incorrect MAC\n");
    }

}

void sm3_benchmark()
{
	size_t i = 0;
	clock_t start = 0, end = 0;
	double diff = 0, speed = 0;
	uint8_t digest[32] = { 0 };


	for (i = 0; i < LARGE_BUFFER_SIZE; i++)
	{
		g_in[i] = i & 0xFF;
	}

	start = clock();

	sm3(g_in, LARGE_BUFFER_SIZE, digest);

	end = clock();
	diff = end - start;
	diff = diff / CLOCKS_PER_SEC;
	speed = (1.0 * LARGE_BUFFER_SIZE / 1024 / 1024) / diff;
	printf("start = %lu\n", start);
	printf("end = %lu\n", end);
	printf("diff = %.03f\n", diff);

	printf("Hash %dMB data in %5.3f second!\n", 500, diff);
	printf("SM3 speed: %.03f MB/sec\n\n", speed);
}


void sm3_hmac_benchmark() {
    size_t i = 0;
    clock_t start = 0, end = 0;
    double diff = 0, speed = 0;
    u1 key[] = "777";
	size_t keylen = strlen((char *)key);
    u1 mac[32] = {0};

    start = clock();

    sm3_hmac(g_in, LARGE_BUFFER_SIZE, key, keylen, mac);

    end = clock();
    diff = end - start;
    diff = diff / CLOCKS_PER_SEC;
    speed = (1.0 * LARGE_BUFFER_SIZE / 1024 / 1024) / diff;
    
    printf("start = %lu\n", start);
    printf("end = %lu\n", end);
    printf("diff = %.03f\n", diff);

    printf("HMAC %dMB data with a %ld-byte key in %5.3f seconds!\n", 500, keylen, diff);
    printf("SM3-HMAC speed: %.03f MB/sec\n\n", speed);
}


void get_TiTable()
{
	int i = 0;
	int table[64] = { 0 };
	int ti = 0;

	ti = 0x79CC4519;
	for (i = 0; i < 16; i++)
	{
		table[i] = ROTATELEFT(ti, i);
	}

	ti = 0x7A879D8A;
	for (; i < 64; i++)
	{
		table[i] = ROTATELEFT(ti, i);
	}

	puts("Ti table:");
	for (i = 0; i < 64; i++)
	{
		printf("0x%08X, ", table[i]);
		if ((i + 1) % 8 == 0)
		{
			puts("");
		}
	}
	puts("");
}


int main()
{
	sm3_self_check();
	sm3_benchmark();
	
	// sm3_hmac_self_check();
	// sm3_hmac_benchmark();
	// //get_TiTable();
	return 0;
}


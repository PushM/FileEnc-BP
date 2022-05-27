#pragma   once  
#include <stdio.h>

#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

typedef struct KEY_SCHEDULE {
	ALIGN16 unsigned char KEY[16 * 15];
	unsigned int nr;
}AES_KEY;
struct thread_parameter //pthread传参结构体
{
	unsigned char* cipher;
	unsigned char* mac;
	int thread_index;
	int n;
	int thread_num;
	int char_num;
};
void File_AES128_ECB_ENC(unsigned char *mykey, char *plainfilename, char *cipherfilename);

inline void print_str(unsigned char *str, int n)
{
	for (int i = 0; i < n; i++) {
		printf("%c", str[i]);
	}
	printf("\n");
}
inline void StrResever(char *str)
{
	char tmp;
	int len = strlen(str);
	for (int i = 0, j = len - 1;i <= j;i++, j--)
	{
		tmp = str[i];
		str[i] = str[j];
		str[j] = tmp;
	}
	str[len] = '\0';
}
inline void Myitoa(char *str, long long n, long radix)
{
	char *chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int i = 0;
	while (n != 0)
	{
		str[i++] = chars[n%radix];
		n /= radix;
	}
	StrResever(str);
}
inline long long Power(long long n, long k)
{
	long b = n;
	if (k == 0)
		return 1;
	for (long a = k - 1; a > 0; --a)  //for 语句可以用while(a--)代替
	{
		n = n * b;   //不能使用n=n*n这样的表达式，会造成数值的混乱
	}
	return n;
}

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void find_key(int n, int thread_num, int model);
void *thread_search(void *arg);
void generate_demo(unsigned char  *mykey);
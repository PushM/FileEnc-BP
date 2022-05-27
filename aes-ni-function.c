#include <wmmintrin.h> 
#include <stdio.h>
#include <stdlib.h>
#include "aes.h"


inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2)
{
	__m128i temp3;
	temp2 = _mm_shuffle_epi32(temp2, 0xff);
	temp3 = _mm_slli_si128(temp1, 0x4);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x4);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x4);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp1 = _mm_xor_si128(temp1, temp2);
	return temp1;
}
void AES_128_Key_Expansion(const unsigned char *userkey,
	unsigned char *key)
{
	__m128i temp1, temp2;
	__m128i *Key_Schedule = (__m128i*)key;

	temp1 = _mm_loadu_si128((__m128i*)userkey);
	Key_Schedule[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[1] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[2] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[3] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[4] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[5] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[6] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[7] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[8] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[9] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[10] = temp1;
}

void AES_ECB_encrypt(const unsigned char *in, //pointer to the PLAINTEXT
	unsigned char *out, //pointer to the CIPHERTEXT buffer
	unsigned long length, //text length in bytes
	const char *key, //pointer to the expanded key schedule
	int number_of_rounds) //number of AES rounds 10,12 or 14
{
	__m128i tmp;
	int i, j;
	if (length % 16)
		length = length / 16 + 1;
	else
		length = length / 16;
	for (i = 0; i < length; i++) {
		tmp = _mm_loadu_si128(&((__m128i*)in)[i]);
		tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);
		for (j = 1; j < number_of_rounds; j++) {
			tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
		}
		tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);
		_mm_storeu_si128(&((__m128i*)out)[i], tmp);
	}
}
void AES_ECB_decrypt(const unsigned char *in, //pointer to the CIPHERTEXT
	unsigned char *out, //pointer to the DECRYPTED TEXT buffer
	unsigned long length, //text length in bytes
	const char *key, //pointer to the expanded key schedule
	int number_of_rounds) //number of AES rounds 10,12 or 14
{
	__m128i tmp;
	int i, j;
	if (length % 16)
		length = length / 16 + 1;
	else
		length = length / 16;
	for (i = 0; i < length; i++) {
		tmp = _mm_loadu_si128(&((__m128i*)in)[i]);
		tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);
		for (j = 1; j < number_of_rounds; j++) {
			tmp = _mm_aesdec_si128(tmp, ((__m128i*)key)[j]);
		}
		tmp = _mm_aesdeclast_si128(tmp, ((__m128i*)key)[j]);
		_mm_storeu_si128(&((__m128i*)out)[i], tmp);
	}
}
int AES_set_encrypt_key(const unsigned char *userKey,
	const int bits,
	AES_KEY *key)
{
	if (!userKey || !key)
		return -1;
	if (bits == 128)
	{
		AES_128_Key_Expansion(userKey, key);
		key->nr = 10;
		return 0;
	}
	//else if (bits == 192)
	//{
	//	//AES_192_Key_Expansion(userKey, key);
	//	key->nr = 12;
	//	return 0;
	//}
	//else if (bits == 256)
	//{
	//	AES_256_Key_Expansion(userKey, key);
	//	key->nr = 14;
	//	return 0;
	//}
	return -2;
}
int AES_set_decrypt_key(const unsigned char *userKey,
	const int bits,
	AES_KEY *key)
{
	int  nr;
	AES_KEY temp_key;
	__m128i *Key_Schedule = (__m128i*)key->KEY;
	__m128i *Temp_Key_Schedule = (__m128i*)temp_key.KEY;
	if (!userKey || !key)
		return -1;
	if (AES_set_encrypt_key(userKey, bits, &temp_key) == -2)
		return -2;
	nr = temp_key.nr;
	key->nr = nr;
	Key_Schedule[nr] = Temp_Key_Schedule[0];
	Key_Schedule[nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
	Key_Schedule[nr - 2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
	Key_Schedule[nr - 3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
	Key_Schedule[nr - 4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
	Key_Schedule[nr - 5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
	Key_Schedule[nr - 6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
	Key_Schedule[nr - 7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
	Key_Schedule[nr - 8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
	Key_Schedule[nr - 9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
	if (nr > 10) {
		Key_Schedule[nr - 10] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
		Key_Schedule[nr - 11] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
	}
	if (nr > 12) {
		Key_Schedule[nr - 12] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
		Key_Schedule[nr - 13] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
	}
	Key_Schedule[0] = Temp_Key_Schedule[nr];
	return 0;
}
/*
int main_demo() {
	AES_KEY key;
	AES_KEY decrypt_key;
	uint8_t *PLAINTEXT;
	uint8_t *CIPHERTEXT;
	uint8_t *DECRYPTEDTEXT;
	uint8_t *EXPECTED_CIPHERTEXT=0;
	uint8_t *CIPHER_KEY=0;
	int i, j;
	int key_length=0;
	char c;

	//读明文、加密、写密文
	unsigned long plain_length = 0;
	char plaintxt[200000];
	errno_t err2;
	FILE *in;
	err2 = fopen_s(&in, "Data100k.txt", "rb");
	while ((c = fgetc(in)) != EOF) {
		plaintxt[plain_length] = c;
		plain_length++;
	}
	fclose(in);//读明文到plaintxt

	//mykey = (uint8_t*)malloc(plain_length);
	PLAINTEXT = (uint8_t*)malloc(plain_length);

	memcpy(PLAINTEXT, plaintxt, plain_length);
	//PLAINTEXT = (uint8_t*)malloc(plain_length);
	CIPHERTEXT = (uint8_t*)malloc(plain_length);
	
	unsigned char *mykey = "12345";
	MD5_CTX md5_key;
	MD5Init(&md5_key);
	unsigned char KEY_128[16];
	MD5Update(&md5_key, mykey, strlen((char*)mykey));//原始的mykey大小。。。
	MD5Final(&md5_key, KEY_128);
	CIPHER_KEY = KEY_128;

	EXPECTED_CIPHERTEXT = ECB128_EXPECTED;
	key_length = 128;

	AES_set_encrypt_key(CIPHER_KEY, key_length, &key);
	AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);
	AES_ECB_encrypt(PLAINTEXT,
		CIPHERTEXT,
		plain_length,
		key.KEY,
		key.nr);
	
	errno_t err;
	FILE *fp;
	err = fopen_s(&fp, "ciphertxt.txt", "wb");
	if (plain_length % 16 == 0) {
		for (j = 0; j < plain_length;j++)
			fputc(CIPHERTEXT[j], fp);
	}
	else {
		for (j = 0; j < plain_length + (16 - plain_length % 16);j++)
			fputc(CIPHERTEXT[j], fp);
	}
	//fclose(fp);//将加密后的文本写入txt
	MD5_CTX md5;
	MD5Init(&md5);
	unsigned char md5_done[16];
	MD5Update(&md5, PLAINTEXT, plain_length);
	MD5Final(&md5, md5_done);
	for (j = 0; j < 16;j++) {
		fputc(md5_done[j], fp);
	}//将hash结果写入txt
	fclose(fp);
	// 加密end

	//解密begin
	unsigned char ciphertxt[200000];
	unsigned long cipher_length = 0;

	errno_t err6;
	FILE *read_cipherfile;
	err6 = fopen_s(&read_cipherfile, "ciphertxt.txt", "rb");
	while (!feof(read_cipherfile)) {
		c = fgetc(read_cipherfile);
		//if (c == '\n') continue;
		ciphertxt[cipher_length] = c;
		cipher_length++;
	}
	fclose(read_cipherfile);//读密文到ciphertxt
	uint8_t *cipher, *mac;
	cipher_length = cipher_length - 1;//因为会把结束标识符255/-1也读出来
	cipher_length = cipher_length - 16;
	cipher = (uint8_t*)malloc(cipher_length );
	mac = (uint8_t*)malloc(16);
	
	memcpy(cipher, ciphertxt,cipher_length );
	memcpy(mac, ciphertxt + cipher_length , 16);
	DECRYPTEDTEXT = (uint8_t*)malloc(cipher_length);
	//for (i = 0;i < plain_length;i++) {
	//	if (cipher[i] != CIPHERTEXT[i])
	//		printf("%d", i);
	//}


	AES_ECB_decrypt(cipher,//cipher是一样的。。。
		DECRYPTEDTEXT,
		107406,
		decrypt_key.KEY,
		decrypt_key.nr);


	MD5_CTX md5_dec;//比较mac值。
	MD5Init(&md5_dec);
	unsigned char md5_dec_value[16];
	MD5Update(&md5_dec, DECRYPTEDTEXT, 107406 );
	MD5Final(&md5_dec, md5_dec_value);
	
	print_str(mac, 16);
	printf("\n");
	print_str(md5_dec_value ,16);


	//print_str(DECRYPTEDTEXT, plain_length);
	//printf(DECRYPTEDTEXT[0]);
	errno_t err5;
	FILE *plain_final;
	err5 = fopen_s(&plain_final, "plain_final.txt", "wb");
	for ( j = 0; j < 107406;j++)//要减去扩展补0的位
		//fprintf( fp, "%c" , cipher[j]);
		fputc(DECRYPTEDTEXT[j], plain_final);
	fclose(plain_final);//将加密后的文本写入plain_final.txt
	//return 0;
//////////////////////////////////////////////////////////////////////

}
*/
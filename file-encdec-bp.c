#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>
#include<stdlib.h>   
#include<string.h>
#include"md5_2.h" 
#include <windows.h>
#include <pthread.h>
#pragma comment(lib, "pthreadVC2.lib")
#include "aes.h"
#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

/*test vectors were taken from http://csrc.nist.gov/publications/nistpubs/800-
38a/sp800-38a.pdf*/

/*****************************************************************************/

/*****************************************************************************/
void File_AES128_ECB_ENC(unsigned char *mykey , char *plainfilename , char *cipherfilename) {

	LARGE_INTEGER nFreq, nBeginTime, nEndTime, begin, end;//time beigin
	double time;
	QueryPerformanceFrequency(&nFreq);
	QueryPerformanceCounter(&begin);
	
	AES_KEY key;
	//AES_KEY decrypt_key;
	uint8_t *PLAINTEXT;
	uint8_t *CIPHERTEXT;
	uint8_t *CIPHER_KEY = 0;
	int i, j;
	int key_length = 128;
	char c;

	//�����ġ����ܡ�д����
	unsigned long plain_length = 0;
	char plaintxt[200000];
	errno_t err2;
	FILE *in;
	err2 = fopen_s(&in, plainfilename, "rb");
	while ((c = fgetc(in)) != EOF) {
		plaintxt[plain_length] = c;
		plain_length++;
	}
	fclose(in);//�����ĵ�plaintxt
	if (plain_length % 16 != 0) {
		int padding = 16 - plain_length % 16;
		for(i = 0;i < padding;i++)
			plaintxt[plain_length++] = -1;
	}
	/*int padding = 16 - plain_length % 16;
	plain_length = plain_length + padding;*/
	PLAINTEXT = (uint8_t*)malloc(plain_length);
	memcpy(PLAINTEXT, plaintxt, plain_length);
	CIPHERTEXT = (uint8_t*)malloc(plain_length);

	MD5_CTX md5_key;
	MD5Init(&md5_key);
	unsigned char KEY_128[16];
	MD5Update(&md5_key, mykey, strlen((char*)mykey));//ԭʼ��mykey��С������
	MD5Final(&md5_key, KEY_128);
	CIPHER_KEY = KEY_128;


	AES_set_encrypt_key(CIPHER_KEY, key_length, &key);
	//AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);

	AES_ECB_encrypt(PLAINTEXT,
		CIPHERTEXT,
		plain_length,
		key.KEY,
		key.nr);

	errno_t err;
	FILE *fp;
	err = fopen_s(&fp, cipherfilename, "wb");
	if (plain_length % 16 == 0) {
		for (j = 0; j < plain_length;j++)
			fputc(CIPHERTEXT[j], fp);
	}
	else {
		for (j = 0; j < plain_length + (16 - plain_length % 16);j++)
			fputc(CIPHERTEXT[j], fp);
	}
	//fclose(fp);//�����ܺ���ı�д��txt

	MD5_CTX md5;
	MD5Init(&md5);
	unsigned char md5_done[16];
	MD5Update(&md5, PLAINTEXT, plain_length);
	MD5Final(&md5, md5_done);
	for (j = 0; j < 16;j++) {
		fputc(md5_done[j], fp);
	}//��hash���д��txt
	fclose(fp);
	QueryPerformanceCounter(&end);
	time = (double)(end.QuadPart - begin.QuadPart) / (double)nFreq.QuadPart;
	
	printf("AES-128-ECB���ܳɹ�����Կ:%s ,����д��%s \n", mykey, cipherfilename);
	printf("���� ʱ�� : %f s \n", time);//time end
	// ����end
}
 int File_AES128_ECB_DEC(unsigned char *mykey,char *cipherfilename ,char *decfilename ) {
	//����begin
	 LARGE_INTEGER nFreq, nBeginTime, nEndTime ,begin , end ;//time beigin
	 double time;
	 QueryPerformanceFrequency(&nFreq);
	 QueryPerformanceCounter(&begin);
	AES_KEY decrypt_key;
	unsigned char ciphertxt[200000];
	unsigned long cipher_length = 0;
	unsigned char *DECRYPTEDTEXT;
	unsigned char *CIPHER_KEY;
	char c;
	int key_length = 128;

	
	//QueryPerformanceFrequency(&nFreq);
	//QueryPerformanceCounter(&nBeginTime);


	MD5_CTX md5_key;
	MD5Init(&md5_key);
	unsigned char KEY_128[16];
	MD5Update(&md5_key, mykey, strlen((char *)mykey));//ԭʼ��mykey��С��������Ҫ��mykey�ĳ���
	MD5Final(&md5_key, KEY_128);
	CIPHER_KEY = KEY_128;
	AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);//���ɽ�����Կ

	//QueryPerformanceCounter(&nEndTime);
	//time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
	//printf("key_hash time : %f s \n", time);//time end

	errno_t err6;
	FILE *read_cipherfile;
	err6 = fopen_s(&read_cipherfile, cipherfilename, "rb");
	while (!feof(read_cipherfile)) {
		c = fgetc(read_cipherfile);
		//if (c == '\n') continue;
		ciphertxt[cipher_length] = c;
		cipher_length++;
	}
	fclose(read_cipherfile);//�����ĵ�ciphertxt
	unsigned char *cipher, *mac;
	cipher_length = cipher_length - 1;//��Ϊ��ѽ�����ʶ��255/-1Ҳ������
	cipher_length = cipher_length - 16;
	cipher = (uint8_t*)malloc(cipher_length);
	mac = (uint8_t*)malloc(16);

	memcpy(cipher, ciphertxt, cipher_length);
	memcpy(mac, ciphertxt + cipher_length, 16);
	DECRYPTEDTEXT = (uint8_t*)malloc(cipher_length);

	//QueryPerformanceFrequency(&nFreq);
	//QueryPerformanceCounter(&nBeginTime);

	AES_ECB_decrypt(cipher,//cipher��һ���ġ�����
		DECRYPTEDTEXT,
		cipher_length,
		decrypt_key.KEY,
		decrypt_key.nr);

	//QueryPerformanceCounter(&nEndTime);
	//time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
	//printf("dec_cipher time : %f s \n", time);//time end

	//QueryPerformanceFrequency(&nFreq);
	//QueryPerformanceCounter(&nBeginTime);
	MD5_CTX md5_dec;//�Ƚ�macֵ��
	MD5Init(&md5_dec);
	unsigned char md5_dec_value[16];
	MD5Update(&md5_dec, DECRYPTEDTEXT, cipher_length);
	MD5Final(&md5_dec, md5_dec_value);

	//QueryPerformanceCounter(&nEndTime);
	//time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
	//printf("plain_hash_&_compare time : %f s \n", time);//time end

	int flag = 0;
	for (int i = 0;i < 16;i++) {
		if (mac[i] != md5_dec_value[i])
			flag = 1;
	}

	printf("AES-128-ECB ��������Կ ��%s�����ܺ������д��%s  ",mykey, decfilename);
	if (flag == 1)printf("���ܳ���\n");
	else {
		printf("������ȷ\n");


		//print_str(DECRYPTEDTEXT, plain_length);
		//printf(DECRYPTEDTEXT[0]);
		errno_t err5;
		FILE *plain_final;
		err5 = fopen_s(&plain_final, decfilename, "wb");
		for (int j = 0; j < cipher_length;j++)//Ҫ��ȥ��չ��0��λ
			//fprintf( fp, "%c" , cipher[j]);
			fputc(DECRYPTEDTEXT[j], plain_final);
		fclose(plain_final);//�����ܺ���ı�д��plain_final.txt
		QueryPerformanceCounter(&end);
		time = (double)(end.QuadPart - begin.QuadPart) / (double)nFreq.QuadPart;
		printf("����ʱ�� : %f s \n", time);//time end
	}
	return flag;
}
void generate_demo(unsigned char  *mykey) {
	char *plain_file = "Data100k.txt";
	char *cipher_file = "cipher.txt";
	char *dec_file = "plain_final.txt";
	File_AES128_ECB_ENC( mykey , plain_file, cipher_file);
	File_AES128_ECB_DEC( mykey , cipher_file, dec_file);

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//int flag = 1;
int goon = 1;
unsigned long cipher_length = 0;

void *thread_search(void *arg) {
	
	struct thread_parameter *parg;
	parg = (struct parameter *) arg;
	unsigned char *cipher = parg->cipher;
	unsigned char *mac = parg->mac;
	long index = parg->thread_index;
	long n = parg->n;
	long thread_num = parg->thread_num;
	long char_num = parg->char_num;
	unsigned char *DECRYPTEDTEXT;
	unsigned char *CIPHER_KEY;
	//int key_length = 128;
	AES_KEY decrypt_key;
	char *cipher_file = "cipher.txt";
	char *dec_file = "plain_final.txt";
	char k[16]="";unsigned char key[16];
	//�������ŵ�ѭ��֮�⡣�������ö�

	DECRYPTEDTEXT = (uint8_t*)malloc(cipher_length);

	for ( long long i = Power(char_num, n)* index /thread_num - 1;i > 0;i--) {
		if (goon == 0) break;
		LARGE_INTEGER nFreq, nBeginTime, nEndTime;
		double time;
		QueryPerformanceFrequency(&nFreq);
		QueryPerformanceCounter(&nBeginTime);

		//_itoa_s(i, k, 16, 10);
		Myitoa(k, i, char_num);//����char_num��10��ʾ��Կֻ�����֣���36��ʾ���ּ���ĸ����62��ʾ��Сд������
		memcpy(key, k, n+1);//�ѽ�β��\0Ҳ����ȥ��


		//int flag=File_AES128_ECB_DEC(key, cipher_file, dec_file);


		MD5_CTX md5_key;
		MD5Init(&md5_key);
		unsigned char KEY_128[16];
		MD5Update(&md5_key, key, strlen((char*)key));//ԭʼ��mykey��С������
		MD5Final(&md5_key, KEY_128);
		CIPHER_KEY = KEY_128;
		AES_set_decrypt_key(CIPHER_KEY, 128, &decrypt_key);//���ɽ�����Կ


		AES_ECB_decrypt(cipher,
			DECRYPTEDTEXT,
			cipher_length,
			decrypt_key.KEY,
			decrypt_key.nr);


		MD5_CTX md5_dec;//�Ƚ�macֵ��
		MD5Init(&md5_dec);
		unsigned char md5_dec_value[16];
		MD5Update(&md5_dec, DECRYPTEDTEXT, cipher_length);
		MD5Final(&md5_dec, md5_dec_value);

		//print_str(mac, 16);
		//printf("\n");
		//print_str(md5_dec_value, 16);
		int flag = 0;
		for (int i = 0;i < 16;i++) {
			if (mac[i] != md5_dec_value[i])
				flag = 1;
		}
		//printf(key);
		if (flag == 1)printf("%s���ܳ���\n", key);
		else {
			printf("������ȷ����ԿΪ��%s\n", key);
			goon = 0;
			//print_str(DECRYPTEDTEXT, plain_length);
			//printf(DECRYPTEDTEXT[0]);
			errno_t err5;
			FILE *plain_final;
			err5 = fopen_s(&plain_final, dec_file, "wb");
			for (int j = 0; j < cipher_length;j++)//Ҫ��ȥ��չ��0��λ
				//fprintf( fp, "%c" , cipher[j]);
				fputc(DECRYPTEDTEXT[j], plain_final);
			fclose(plain_final);//�����ܺ���ı�д��plain_final.txt
		}
		
		QueryPerformanceCounter(&nEndTime);
		time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
		printf("one try : %f s \n", time);
		if (flag == 0) break;
	}
	
	
}

void find_key(  int n , int thread_num ,int model ) {
	LARGE_INTEGER nFreq, nBeginTime, nEndTime;
	double time;
	QueryPerformanceFrequency(&nFreq);
	QueryPerformanceCounter(&nBeginTime);
	//char k[16];unsigned char key[16];
	char *cipher_file = "cipher.txt";
	//char *dec_file = "plain_final.txt";
	//AES_KEY decrypt_key;
	unsigned char ciphertxt[200000];	
	//unsigned char *DECRYPTEDTEXT;
	//unsigned char *CIPHER_KEY;
	char c;
	int i;int char_num;
	//int key_length = 128;
	switch (model)
	{
	case 0:
		char_num = 10;break;
	case 1:
		char_num = 36;break;
	case 2:
		char_num = 62;break;
	default:
		char_num = 62;break;
	}

	errno_t err6;
	FILE *read_cipherfile;
	err6 = fopen_s(&read_cipherfile, cipher_file, "rb");
	while (!feof(read_cipherfile)) {
		c = fgetc(read_cipherfile);
		//if (c == '\n') continue;
		ciphertxt[cipher_length] = c;
		cipher_length++;
	}
	fclose(read_cipherfile);//�����ĵ�ciphertxt
	unsigned char *cipher, *mac;
	cipher_length = cipher_length - 1;//��Ϊ��ѽ�����ʶ��255/-1Ҳ������
	cipher_length = cipher_length - 16;
	cipher = (uint8_t*)malloc(cipher_length);
	mac = (uint8_t*)malloc(16);

	memcpy(cipher, ciphertxt, cipher_length);
	memcpy(mac, ciphertxt + cipher_length, 16);

	struct thread_parameter *arg;
	arg = (struct thread_parameter*)malloc(sizeof(struct thread_parameter)*thread_num);

	for ( i = 0;i < thread_num;i++) {
		arg[i].cipher = cipher;
		arg[i].mac = mac;
		arg[i].n = n;
		arg[i].thread_num = thread_num;
		arg[i].thread_index = i + 1;
		arg[i].char_num = char_num;
	}
	//pthread_t t[8];
	pthread_t *t;
	t = (pthread_t*)malloc(sizeof(pthread_t)*thread_num);

	for (i = 0;i < thread_num;i++) {
		pthread_create(&t[i], NULL, thread_search, &arg[i]);
	}

	for (i = 0;i < thread_num;i++) {
		pthread_join(t[i], NULL);
	}
	QueryPerformanceCounter(&nEndTime);
	time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
	//printf("���ѳ���Կ ��%s", final_key);
	printf("����ʱ�� : %f s \n", time);
}
//int main() {
//
//	LARGE_INTEGER nFreq, nBeginTime, nEndTime;
//	double time;
//	QueryPerformanceFrequency(&nFreq);
//	QueryPerformanceCounter(&nBeginTime);
//	generate_demo("zzzzz0");
//	//find_key(4,8,1);//����char_num��0��ʾ��Կֻ�����֣���1��ʾ���ּ���ĸ����3��ʾ��Сд������
//	QueryPerformanceCounter(&nEndTime);
//	time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
//	printf("enc time : %f s \n", time );
//	return 0;
//}

#include "aes.h"
int main() {
	
	printf("CPU support AES instruction set.\n\n");
	char *plain_file = "Data100k.txt";//明文
	char *cipher_file = "cipher.txt";//密文
	char *dec_file = "plain_final.txt";//解密后的明文
	
	char *mykey = "80603";//密钥

	//File_AES128_ECB_ENC(mykey, plain_file, cipher_file);//文件AES-128-ECB加密
	//File_AES128_ECB_DEC(mykey, cipher_file, dec_file);//文件AES-128-ECB解密
	find_key(5,8,0);//穷搜密钥，
	//n表示密钥位数，thread_nuum表示穷搜的线程数
	//这里char_num置0表示密钥只有数字，置1表示密钥有数字和小写字母。置3表示有大小写字母加数字

	return 0;
}
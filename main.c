#include "aes.h"
int main() {
	
	printf("CPU support AES instruction set.\n\n");
	char *plain_file = "Data100k.txt";//����
	char *cipher_file = "cipher.txt";//����
	char *dec_file = "plain_final.txt";//���ܺ������
	
	char *mykey = "80603";//��Կ

	//File_AES128_ECB_ENC(mykey, plain_file, cipher_file);//�ļ�AES-128-ECB����
	//File_AES128_ECB_DEC(mykey, cipher_file, dec_file);//�ļ�AES-128-ECB����
	find_key(5,8,0);//������Կ��
	//n��ʾ��Կλ����thread_nuum��ʾ���ѵ��߳���
	//����char_num��0��ʾ��Կֻ�����֣���1��ʾ��Կ�����ֺ�Сд��ĸ����3��ʾ�д�Сд��ĸ������

	return 0;
}
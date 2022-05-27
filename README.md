# FileEnc-BP
对文件AES-ni+MD5加解密，多线程穷搜

## 设计加解密系统——AES加密MD5计算摘要

### 1、关于aes-ni以及系统函数设计

本加解密系统使用AES-128-ECB进行文件的加解密，但关于汉字的加解密因为时间关系还未完全解决编码格式问题，基于aes-ni实现。

**高级加密标准指令集**（或称英特尔高级加密标准新指令，简称**AES-NI**）是一个x86指令集架构的扩展，用于Intel和AMD微处理器，由Intel在2008年3月提出。[1]该指令集的目的是改进应用程序使用高级加密标准（AES）执行加密和解密的速度。

本人笔记本使用的cpu为intel的酷睿i5处理器，支持AES-NI，并通过了检测代码验证。wmmintrin.h头文件中包含了AES-NI指令，在编写代码时需要引入。

通过intel-AES-NI的白皮书，找到了如下函数：

```c
int AES_set_encrypt_key(const unsigned char *userKey,
	const int bits,
	AES_KEY *key)//基于128bit的userkey生成加密密钥
int AES_set_decrypt_key(const unsigned char *userKey,
	const int bits,
	AES_KEY *key)//基于128bit的userkey生成解密密钥
void AES_ECB_encrypt(const unsigned char *in, //pointer to the PLAINTEXT
	unsigned char *out, //pointer to the CIPHERTEXT buffer
	unsigned long length, //text length in bytes
	const char *key, //pointer to the expanded key schedule
	int number_of_rounds) //number of AES rounds 10,12 or 14
void AES_ECB_decrypt(const unsigned char *in, //pointer to the CIPHERTEXT
	unsigned char *out, //pointer to the DECRYPTED TEXT buffer
	unsigned long length, //text length in bytes
	const char *key, //pointer to the expanded key schedule
	int number_of_rounds) //number of AES rounds 10,12 or 14
void AES_128_Key_Expansion(const unsigned char *userkey,
	unsigned char *key)
```

利用这些函数实现了File_AES128_ECB_ENC函数以及File_AES128_ECB_DEC函数。

```c
void File_AES128_ECB_ENC(unsigned char *mykey ,
char *plainfilename , 
char *cipherfilename) 

void File_AES128_ECB_DEC(unsigned char *mykey,
char *cipherfilename ,
char *decfilename ) 
```

### 2、File_AES128_ECB_ENC函数细节：

分为**密钥哈希，读明文加密，计算信息摘要**三部分

1、密钥哈希

首先是密钥哈希，AES-128的密钥长度为128bit，而我们设定的密钥一般为不会是128bit，即不等于16个字符，这时需要进行扩展。我们组选用MD5进行hash，MD5hash后的结果也正好为128bit，而且由于密钥比较短，hash密钥比加密所用时间小得多。

```c
	MD5_CTX md5_key;
	MD5Init(&md5_key);
	unsigned char KEY_128[16];
	MD5Update(&md5_key, mykey, strlen((char*)mykey));//原始的mykey大小。
	MD5Final(&md5_key, KEY_128);
	CIPHER_KEY = KEY_128;
```

2、读明文加密

之后从明文文件plainfilename中读字符（默认”\n“换行符也读，为了保留源文件格式）存入足够大的字符数组中，记录明文长度plain_length，之后要填充明文长度为16的倍数。

> 虽然不填充的明文导入AES-NI的 AES_ECB_encrypt函数中不会出错，且函数内部应该已经实现填充操作，但我们要计算摘要值，如果我们计算的是填充前明文的摘要值，那么在明文填充后解密得到的是填充后的明文，而且由于不知道填充前明文的长度，不知道应该删去多少。基于这个问题，我们组的解决方法是进入AES_ECB_encrypt函数便填充-1至128bit的倍数（即无符号字符数组长度为16的倍数），plain_length也随之增加。

按plain_length为unsigned char型数组PLAINTEXT、CIPHERTEXT分配空间，PLAINTEXT存扩展后的明文，CIPHERTEXT用于存之后加密后的密文。

利用AES-NI的AES_set_encrypt_key函数，得到AES_KEY类型的key。之后执行AES_ECB_encrypt函数。

```c
	AES_set_encrypt_key(CIPHER_KEY, key_length, &key);
	AES_ECB_encrypt(PLAINTEXT,
		CIPHERTEXT,
		plain_length,
		key.KEY,
		key.nr);
```

之后将加密后的密文CIPHERTEXT写入文件cipherfilename。

3、计算信息摘要——MD5

计算扩展后明文的MD5值（128bit），写入密文作为信息摘要值。

```
MD5_CTX md5;
	MD5Init(&md5);
	unsigned char md5_done[16];
	MD5Update(&md5, PLAINTEXT, plain_length);
	MD5Final(&md5, md5_done);
	for (j = 0; j < 16;j++) {
		fputc(md5_done[j], fp);
	}//将hash结果写入txt
	fclose(fp);
```

加密结束。密文文件展示：

![image-20220527171250748](../../../Typora/typora-pic/image-20220527171250748.png)

### 3、File_AES128_ECB_DEC函数细节

File_AES128_ECB_DEC函数同加密函数差不多，分为**密钥哈希，读密文解密，比较信息摘要**。

1、密钥哈希：

同加密。

2、读密文解密：

首先从密文文件cipherfilename中读出密文，将密文分为密文和信息摘要，信息摘要为最后128bit（16个char字符），密文为读出来的字符除去最后128bit。得到密文cipher，信息摘要mac，密文长度cipher_length。

之后调用AES-NI的函数，生成解密密钥，解密。

```c
	AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);//生成解密密钥
	AES_ECB_decrypt(cipher,
		DECRYPTEDTEXT,
		cipher_length,
		decrypt_key.KEY,
		decrypt_key.nr);
```

3、比较信息摘要：

计算解密后的明文DECRYPTEDTEXT的md5值与信息摘要mac比较，正确的话写入解密文件decfilename，错误的话打印解密出错。

解密后的文件：

![image-20220527171259412](../../../Typora/typora-pic/image-20220527171259412.png)

原始明文文件：

![image-20220527171303723](../../../Typora/typora-pic/image-20220527171303723.png)

## c语言AES-NI加速+pthread多线程

由于python实现破解是调用库函数实现，虽然查找资料显示python的aes加密库也是使用aes-ni指令，但实际验证显示c语言AES-NI加速+pthread多线程实现破解要优于python调用库函数+多进程破解。

定义find_key函数

```
void find_key(  int n , int thread_num ,int model )
//n表示密钥位数，thread_nuum表示穷搜的线程数
//这里model置0表示密钥只有数字，置1表示密钥有数字和小写字母。置3表示有大小写字母加数字
```

**find_key函数的设计细节**可以分为**建立多线程、密钥空间的动态选择和线程中的解密验证**。

1、建立多线程：

因为每个线程要解密的文件都是同一个，所以为了性能，就不能在线程中再读文件，而是在主线程读文件然后传给每个线程，这样只读了一次密文。

```c
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
	pthread_t *t;
	t = (pthread_t*)malloc(sizeof(pthread_t)*thread_num);

	for (i = 0;i < thread_num;i++) {
		pthread_create(&t[i], NULL, thread_search, &arg[i]);
	}

	for (i = 0;i < thread_num;i++) {
		pthread_join(t[i], NULL);
	}
```

向每个线程传递的参数有密文字符数组，信息摘要mac值，密钥长度n，线程数thread_num，线程序号thread_index，以及选择密钥空间所需的char_num。

2、密钥空间的动态选择

怎么做到让每个线程穷搜密钥空间的不同部分呢？

```c
for ( long long i = Power(char_num, n)* index /thread_num - 1;i > 0;i--){
	if (goon == 0) break;
	Myitoa(k, i, char_num);//这里char_num置10表示密钥只有数字，置36表示数字加字母。置62表示大小写加数字
```

如果char_num=36，n=4。那么密钥空间大小为$36^{4}$, $i$的大小为0~$36^{4}$，我们可以将i转换为36进制，每一位的从1到36对应数字+小写字母36个字符。这就是Myitoa函数的功能。

```c
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
```

为了减少函数调用，我们将Myitoa、StrResever、Power函数都声明为inline函数。且i的值要定义为long long类型，因为当我们密钥空间为$36^6$时，便超过了long表示的范围。

3、线程中的解密验证

解密验证过程与文件加解密系统中的File_AES128_ECB_DEC函数一样，但若调用该函数，会极大地影响程序性能，于是我们将File_AES128_ECB_DEC函数定义copy到线程中，减少了函数调用时间。一个线程找到正确密钥，其余线程都停止。

- **破解时间**

基于AES-NI、多线程以及函数调用，减少不必要地重复计算，得到优化后地破解速度：

**1、理论最长破解时间：**

仅密钥哈希、解密、计算信息摘要并比较的时间（稳定后）大致在0.001s到0.002s之间

![image-20220527171323370](../../../Typora/typora-pic/image-20220527171323370.png)

所以我们按照0.0015s的一次验证时间、开启了8个线程估测最长所需破解时间：

4位纯数字密钥：$10^4\times0.0015\div8=1.875s$

4位数字+小写字母密钥：$36^4\times0.0015\div8=231s$

5位纯数字密钥：$10^5\times0.0015\div8=13.75s$

5位数字+小写字母密钥：$36^5\times0.0015\div8=8314s=138.5mins$

6位纯数字密钥：$10^6\times0.0015\div8=137.5s$

6位数字+小写字母密钥：$36^6\times0.0015\div8=299307s=4988mins=83h$

（实际应加上创建线程时间、一次读明文和一次写解密明文的时间。）



**2、实际测试破解时间示例**：

**4位纯数字密钥：**

| 密钥值\线程数 | 2         | 4         | 8         |
| ------------- | --------- | --------- | --------- |
| 7777          | 5.146609s | 6.483821s | 5.802197s |
| 7250          | 5.786570s | 1.576311s | 2.446894s |

**4位数字+小写字母密钥：**

| 密钥值\线程数 | 2           | 4           | 8           |
| ------------- | ----------- | ----------- | ----------- |
| 5678          | 860.504997s | 339.76849s  | 254.394327s |
| uzi6          | 337.171244s | 330.722751s | 45.112301s  |

**5位纯数字密钥：**

| 密钥值\线程数 | 2          | 4          | 8          |
| ------------- | ---------- | ---------- | ---------- |
| 20603         | 42.142266s | 10.815166s | 12.759463s |
| 80603         | 25.095383s | 27.162996s | 17.525872s |

**6位纯数字密钥：**

| 密钥值\线程数 | 2           | 4           | 8          |
| ------------- | ----------- | ----------- | ---------- |
| 617250        | 423.569001s | 181.362841s | 17.525820s |
| 323456        | 250.592012s | 213.254685s | 96.080300s |

因为测试cpu为4核8线程，当提高线程数为10、12时发现运行时间不会再有提升。

## 未实现

1、仅加速了aes加解密的过程，没有对md5也进行加速。但了解到了**SIMD-md5**的实现，可以使用**sse指令集**对4个字符串并行进行md5哈希，也可以使用**avx指令**对8个字符串并行进行哈希，设想这便可以生成8个密钥，然后生成8个解密明文，对这8个解密明文并行md5哈希，检测有没有等于原始明文消息摘要值的。



## 总结与反馈

本次实验是设计一个文件加解密系统，并写一个穷搜破解密钥的程序。

实验中我们组用到了python多进程编程、python crypt模块的使用、c语言多线程编程、AES-NI指令集技术、字符编码格式，并熟悉了设计一个完成程序系统的规范，帮助组员们提高了编程水平。实验过程中体会到了对编程语言这一工具以及ide软件的不熟练，这使得在程序实现上花费了太多时间，之后的时间里应该多写代码，提高对编程语言的熟练程度。

实验结果符合预期，把一次验证密钥的时间缩小到了0.001s~0.002s，也体会到了密钥空间太大，穷搜密钥的时间复杂度会很高，而多线程技术仅从常量级别减少时间，还应继续从减小验证密钥时间入手优化破解程序。但同时也体会到了只要密钥空间足够大，是很难用穷搜破解的。
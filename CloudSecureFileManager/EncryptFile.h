#include "stdafx.h"
#include "openssl\evp.h"
#include "openssl\aes.h"
#include "openssl\err.h"
#include "openssl\rand.h"
#include "openssl\pem.h"
#include "openssl\bio.h"
#include "openssl\rsa.h"
#include "openssl\md5.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdio.h>
#include "Wbemcli.h"

#pragma comment(lib,"Wbemuuid.lib")
#define FILE_DELIMITER_SIZE 64
#define MAX_FILE_READ_SIZE 10000
#define TAG_LEN 16
#define RSA_KEY_SIZE 4096
#define RSA_DATA_SIZE 512
#define IV "zW1CoIXHuBGn4bf"
using namespace std;
struct EncryptedFileData
{
	__int64 startDelimiter;
	CStringA fileExtension;
	unsigned char * key;
};
struct Public_Private_Key
{
	char* publicKey;
	char* privateKey;
};
struct HardwareIds
{
	char* cpu;
	char* hardDrive;
};
class FileEncrypt
{
	public:
		bool EncryptFile(wchar_t* filePath,char* delimiter,Public_Private_Key keypairs,unsigned char* tagExtension,unsigned char* tagFile);
		bool DecryptFile(wchar_t* filePath,char* delimiter,Public_Private_Key keypairs,unsigned char* tagExtension,unsigned char* tagFile);
		Public_Private_Key GeneratePublicPrivateKey(int bits);
		void ClearKeyPairs(Public_Private_Key keyPairs);
		char* GenerateDelimiter();
	private:
		int Encrypt(EVP_CIPHER_CTX * ctx,unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len,unsigned char *ciphertext,unsigned char * tag,bool update,bool final);
		void handleErrors(void);
		EVP_CIPHER_CTX * InitCipher(unsigned char *key, unsigned char *iv,bool encrypt,bool decrypt);

		int Decrypt(EVP_CIPHER_CTX * ctx,unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,//no point for aad
            int aad_len,unsigned char *plaintext,unsigned char * tag,bool udpate,bool final);
		bool GenerateAESKey(unsigned char * buffer,long size);
		bool GenerateMD5HashFile(wchar_t* filePath,unsigned char* hash);
		bool EncryptKeyPP(unsigned char* plaintextKeyAes,unsigned char* encryptedKeyRSA,Public_Private_Key keypairs);
		bool DecryptKeyPP(unsigned char* encryptedKeyRSA,unsigned char* plaintextAes,Public_Private_Key keypairs);
		RSA* GetRSADataFromPlainTextKey(char* plaintextKey,bool public_private);
		EncryptedFileData FindKeyStart(wchar_t* filePath,char* delimiter,Public_Private_Key keypairs,unsigned char * tag);
		HardwareIds GetHardWareIds(); // make private after testing
};
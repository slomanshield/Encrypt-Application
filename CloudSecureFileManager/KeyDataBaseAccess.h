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

#import <C:\\Windows\\System32\\msxml6.dll>
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"Wbemuuid.lib")
#define MAX_FILE_READ_SIZE 10000
#define FILE_DELIMITER_SIZE 64
#define FILE_TEST_PASS_DATA_LENGTH 64
#define LENGTH_XML_INDENIFER 4
#define FILE_FLAG_LENGTH 1 
#define TAG_LEN 16
#define USE_PASS_AND_HARDWARE 0x02
#define USE_ONLY_PASS 0x01
#define DATABASE_KEY_FILE_NAME "KeyDataBase.xrx"
#define DATABASE_KEY_TEMP_FILE_NAME "KeyDataBase_TEMP.xrx"
#define INITALIZATION_VECTOR "Ro0JWZk6JBO8uZa"
using namespace std;
struct FileParameters
{
	char* delimiter;
	char* hash;
	char* tagExtension;
	char* tagFile;
	char* publicKey;
	char* privateKey;
	wchar_t* fileName;
	bool keep;//use this flag when deleting
};


class KeyDataBaseAccess
{
	public://add in support for wide characters with the password require password and password length in bytes
		FileParameters* GetFileEntry(wchar_t* filePathENCR,unsigned char* key);
		bool SetFileEntry(wchar_t* filePathENCR,char* publicKey, char* privateKey,char* delimiter, unsigned char* key,char* tagExtension,char* tagfile);
		bool CheckPasswd(unsigned char * key);//use this to check password
		bool CheckKeyFileExists();
		bool CreateNewKeyDataBaseFile(bool usePassword,bool useHardwareSerial,unsigned char* key);//will delete file and replace with a 1 byte file wit ha flag
		void ClearFileParams(FileParameters* fileParams);
		void ClearKeyDataBaseList();
		CList<FileParameters*>* GetKeyDataBaseList(unsigned char * key);
		//INPLE,MENT THESE 
		bool DeleteFileEntrys(unsigned char * key);//uses the class list 
		//
	private:
		bool GetSHA256Hash(wchar_t* filePath,unsigned char* hash);//hash must have a size of MD5_DIGEST_LENGTH, only to be used on ppencr 
		void GenerateRandomBytes(unsigned char* bytes,__int64 size);
		char GetFlagFile();
		FileParameters* GetFileParams(char* xmlNodeRaw);
		char* GetStringOfBinary(char* binary,long length);
		char* GetBinaryOfString(char* string,long length,long* outBinaryLength);
		bool CompareHash(char* hash1,char* hash2);
		bool GenerateKeyDataBaseFilePasswd(unsigned char * buffer,long size,unsigned char* seed,long seedLength);//seed is the user password
		bool GenerateKeyDataBaseFilePasswdAndHardware(unsigned char * buffer,long size,unsigned char* seed,long seedLength);//seed is the user password
		unsigned char * GetHardWareUniqueIdHash();
		int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext,unsigned char* tag);
		void handleErrors(void);
		int Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,//no point for aad
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext,unsigned char* tag);
		CList<FileParameters*> keyDatabaseList;
};
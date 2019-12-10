#include "stdafx.h"
#include "KeyDataBaseAccess.h"
#include "wincrypt.h"

void KeyDataBaseAccess::handleErrors()
{
	unsigned long errCode;

    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
    }
    abort();
}
int KeyDataBaseAccess::Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext,unsigned char* tag)
{

	EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;


    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        return -1;
	
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

}

int KeyDataBaseAccess::Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,//no point for aad
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext,unsigned char* tag)
{

	EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        return -1;

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
       return -1;

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }

}

void KeyDataBaseAccess::GenerateRandomBytes(unsigned char* bytes,__int64 size)
{
	srand(time(NULL));
	for(__int64 i = 0; i < size;i++)
	{
		bytes[i] = rand() % 256;
	}
	return;
}

void KeyDataBaseAccess::ClearFileParams(FileParameters* fileParams)
{
	try{
		delete [] fileParams->delimiter;
		delete [] fileParams->hash;
		delete [] fileParams->privateKey;
		delete [] fileParams->publicKey;
		delete [] fileParams->tagExtension;
		delete [] fileParams->tagFile;
		delete [] fileParams->fileName;
		delete fileParams;
	}
	catch(...)
	{
		return;
	}
}

bool KeyDataBaseAccess::CompareHash(char* hash1, char* hash2)
{
	int hashLength = SHA256_DIGEST_LENGTH;
	for(int i = 0 ; i < hashLength; i++)
	{
		if(hash1[i] == hash2[i])
			continue;
		else
			return false;
	}
	return true;
}
char* KeyDataBaseAccess::GetStringOfBinary(char* binary,long length)
{
	BOOL bSuccess = false;
	DWORD encodedLength = 0;
	char* encodedData;
	CryptBinaryToStringA((BYTE*)binary,length,CRYPT_STRING_BASE64,NULL,&encodedLength);
	encodedData = new char [encodedLength];
	ZeroMemory(encodedData,encodedLength);
	bSuccess = CryptBinaryToStringA((BYTE*)binary,length,CRYPT_STRING_BASE64,encodedData,&encodedLength);
	if(bSuccess)
		return encodedData;
	else 
		return NULL;
}
char* KeyDataBaseAccess::GetBinaryOfString(char* string,long length,long* outBinaryLength)
{
	BOOL bSuccess = false;
	DWORD binaryLength = 0;
	char* binaryData;
	CryptStringToBinaryA(string,length,CRYPT_STRING_BASE64,NULL,&binaryLength,NULL,NULL);
	binaryData = new char [binaryLength];
	ZeroMemory(binaryData,binaryLength);
	bSuccess = CryptStringToBinaryA(string,length,CRYPT_STRING_BASE64,(BYTE*)binaryData,&binaryLength,NULL,NULL);
	if(bSuccess)
	{
		*outBinaryLength = binaryLength;
		return binaryData;
	}
	else 
		return NULL;
}

bool KeyDataBaseAccess::GenerateKeyDataBaseFilePasswdAndHardware(unsigned char * buffer,long size,unsigned char* seed,long seedLength)
{
	if(size != SHA256_DIGEST_LENGTH)
		return false;
	unsigned char * hardwareHash = GetHardWareUniqueIdHash();
	ZeroMemory(buffer,size);
	unsigned char randomSeedKeyBuffer [SHA256_DIGEST_LENGTH+1];
	ZeroMemory(randomSeedKeyBuffer,SHA256_DIGEST_LENGTH+1);
	char tempChar = '\0';//sha 256 hash
	long bufferIndex = 0;
	long seendIndex = 0;
	try
	{
		if(seedLength > size)
		{
			for(long i =0;i < seedLength;i++)
			{
				if(bufferIndex == size)
					bufferIndex = 0;
				tempChar = seed[i];
				srand (tempChar);
				randomSeedKeyBuffer[bufferIndex] = rand() % 256;
				bufferIndex ++;
			}
		}
		else if(seedLength < size)
		{
			for(long i =0;i < size;i++)
			{
				if(seendIndex == seedLength)
					seendIndex = 0;
				tempChar = seed[seendIndex];
				srand (tempChar);
				randomSeedKeyBuffer[i] = rand() % 256;
				seendIndex ++;
			}

		}
		else if(seedLength = size)
		{
			for(long i =0;i < size;i++)
			{
				tempChar = seed[i];
				srand (tempChar);
				randomSeedKeyBuffer[i] = rand() % 256;
				seendIndex ++;
			}

		}
		SHA256_CTX mdContext;
		SHA256_Init (&mdContext);
		SHA256_Update (&mdContext,&randomSeedKeyBuffer[0], SHA256_DIGEST_LENGTH);
		SHA256_Final (randomSeedKeyBuffer,&mdContext);
	}
	catch(...)
	{
		return false;
	}
	unsigned char bothHashs [SHA256_DIGEST_LENGTH*2];
	ZeroMemory(bothHashs,SHA256_DIGEST_LENGTH*2);
	memcpy(bothHashs,hardwareHash,SHA256_DIGEST_LENGTH);
	memcpy(&bothHashs[SHA256_DIGEST_LENGTH],randomSeedKeyBuffer,SHA256_DIGEST_LENGTH);

	//do hash on both hashes

	SHA256_CTX mdContext;
	SHA256_Init (&mdContext);
	SHA256_Update (&mdContext,&bothHashs[0], SHA256_DIGEST_LENGTH*2);
	SHA256_Final (buffer,&mdContext);

	delete [] hardwareHash;

	return true;
}



bool KeyDataBaseAccess::GenerateKeyDataBaseFilePasswd(unsigned char * buffer,long size,unsigned char* seed,long seedLength)
{
	if(size != SHA256_DIGEST_LENGTH)
		return false;
	char tempChar = '\0';//sha 256 hash
	unsigned char randomSeedKeyBuffer [SHA256_DIGEST_LENGTH+1];
	ZeroMemory(randomSeedKeyBuffer,SHA256_DIGEST_LENGTH+1);
	long bufferIndex = 0;
	try
	{
		for(long i =0;i < seedLength;i++)
		{
			if(bufferIndex == size)
				bufferIndex = 0;
			else
				tempChar = seed[i];
			srand (tempChar);
			randomSeedKeyBuffer[bufferIndex] = rand() % 256;
			bufferIndex ++;
		}
		SHA256_CTX mdContext;
		SHA256_Init (&mdContext);
		SHA256_Update (&mdContext,&randomSeedKeyBuffer[0], SHA256_DIGEST_LENGTH);
		SHA256_Final (buffer,&mdContext);
	}
	catch(...)
	{
		return false;
	}
	return true;


}
char KeyDataBaseAccess::GetFlagFile()
{
	char flag = 0;

	fstream fileStream;
	fileStream.open(DATABASE_KEY_FILE_NAME,ios::in | ios::binary);
	fileStream.seekg (0, fileStream.end);
	__int64 fileLength = fileStream.tellg();
	if(fileLength == -1)
		return NULL;
	fileStream.seekg(0,fileStream.beg);
	fileStream.read((char *)&flag,1);//read in flag
	fileStream.close();
	return flag;
}
bool KeyDataBaseAccess::CheckPasswd(unsigned char * key)
{
	char flagVal = GetFlagFile();
	unsigned char realKey [SHA256_DIGEST_LENGTH];
	ZeroMemory(realKey,SHA256_DIGEST_LENGTH);
	bool success = false;
	if(flagVal == USE_PASS_AND_HARDWARE)
	{
		success = GenerateKeyDataBaseFilePasswdAndHardware(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}
	else if (flagVal == USE_ONLY_PASS)
	{
		success = GenerateKeyDataBaseFilePasswd(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));

	}
	fstream inputFileEncrypted;
	inputFileEncrypted.open(DATABASE_KEY_FILE_NAME,ios::in | ios::binary);
	inputFileEncrypted.seekg (0, inputFileEncrypted.end);
	__int64 fileLength = inputFileEncrypted.tellg();
	if(fileLength == -1)
		return NULL;
	__int64 pos = 1;//set to 1 because first byte is flag
	__int64 readAmount = FILE_TEST_PASS_DATA_LENGTH;
	unsigned char * rawInputData = 0;
	unsigned char * rawDecryptedData = 0;
	unsigned char iv [16] = INITALIZATION_VECTOR;
	unsigned char tag[TAG_LEN];
	inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
	inputFileEncrypted.read((char *)&tag[0],TAG_LEN);
	pos += TAG_LEN;

	rawInputData = new unsigned char [readAmount];
	rawDecryptedData = new unsigned char [readAmount];
	ZeroMemory(rawInputData,readAmount);
	ZeroMemory(rawDecryptedData,readAmount);
	inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
	inputFileEncrypted.read((char *)&rawInputData[0],readAmount);
	int valEncrypt = Decrypt(rawInputData,readAmount,NULL,0,realKey,iv,rawDecryptedData,tag);
	delete [] rawInputData;
	delete [] rawDecryptedData;
	inputFileEncrypted.close();
	if(valEncrypt == -1)
	{
		return false;
	}
	else
		return true;
	
}
bool KeyDataBaseAccess::CheckKeyFileExists()
{
	fstream fileStream;
	fileStream.open(DATABASE_KEY_FILE_NAME,ios::in | ios::binary);
	fileStream.seekg (0, fileStream.end);
	__int64 fileLength = fileStream.tellg();
	fileStream.close();
	if(fileLength == -1)
		return false;
	return true;
}
unsigned char * KeyDataBaseAccess::GetHardWareUniqueIdHash()
{
	HW_PROFILE_INFO hardwareInfo;
	GetCurrentHwProfile(&hardwareInfo);
	char* hardwareProfileGUID = (char *)hardwareInfo.szHwProfileGuid;
	unsigned char * GUID_HASH  = new unsigned char [SHA256_DIGEST_LENGTH];
	ZeroMemory(GUID_HASH,SHA256_DIGEST_LENGTH);
	ZeroMemory(GUID_HASH,SHA256_DIGEST_LENGTH);
	int w_GuidLength = wcslen((wchar_t *)hardwareProfileGUID);
	//get 256 hash
	SHA256_CTX mdContext;
	SHA256_Init (&mdContext);
	SHA256_Update (&mdContext,&hardwareProfileGUID[0], w_GuidLength*2);// * 2 because wchar
	SHA256_Final (GUID_HASH,&mdContext);
	return GUID_HASH;
}
bool KeyDataBaseAccess::GetSHA256Hash(wchar_t* filePath,unsigned char* hash)
{
	bool success = false;
	__int64 numRead = 0;
	__int64 pos = 0;
	__int64 readAmount = 0;
	fstream fileInput;
	fileInput.open(filePath,ios::in | ios::binary);
	fileInput.seekg (0, fileInput.end);
	__int64 fileLength = fileInput.tellg();
	if(fileLength == -1)
		return false;
	unsigned char* data;
	SHA256_CTX mdContext;
	SHA256_Init (&mdContext);
	while(fileLength != numRead)
	{
		if((fileLength-pos) >= MAX_FILE_READ_SIZE)
			readAmount = MAX_FILE_READ_SIZE;
		else
			readAmount = fileLength-pos;
		data = new unsigned char [readAmount];
		ZeroMemory(data,readAmount);
		fileInput.seekg(pos,fileInput.beg);
		fileInput.read((char *)&data[0],readAmount);
		int hashSuccess = SHA256_Update (&mdContext,&data[0], readAmount);
		if(hashSuccess == 0)
		{
			delete [] data;
			return false;
		}
		delete [] data;
		numRead += readAmount;
		pos += readAmount;
	}
	SHA256_Final (hash,&mdContext);
	fileInput.close();
	return true;
}

FileParameters* KeyDataBaseAccess::GetFileParams(char* xmlNodeRaw)
{
	CoInitialize(NULL);
	OleInitialize(NULL);
	MSXML2::IXMLDOMDocument2Ptr  doc;
	doc.CreateInstance(__uuidof(MSXML2::DOMDocument60));
	IXMLDOMElementPtr element;
	element.CreateInstance((__uuidof(MSXML2::IXMLDOMElementPtr)));
	IXMLDOMNodePtr node;
	node.CreateInstance((__uuidof(MSXML2::IXMLDOMNodePtr)));
	BSTR bstr_publicKey = L"";
	BSTR bstr_privateKey = L"";
	BSTR bstr_fileDelimiter = L"";
	BSTR bstr_hash = L"";
	BSTR bstr_fileName = L"";
	BSTR bstr_tagExtension = L"";
	BSTR bstr_tagFile = L"";
	CStringA publicKeyStr;
	CStringA privateKeyStr;
	CStringA fileDelimiterStr;
	CStringA hashStr;
	CStringW fileNameStr;
	CStringA tagExtensionStr;
	CStringA tagFileStr;
	FileParameters* fileParams = new FileParameters;
	long binaryLength = 0;
	try
	{
		doc->loadXML(xmlNodeRaw);
		element = doc->GetdocumentElement();
		element->selectSingleNode(L"PublicKey",&node);
		node->get_text(&bstr_publicKey);
		element->selectSingleNode(L"PrivateKey",&node);
		node->get_text(&bstr_privateKey);
		element->selectSingleNode(L"FileDelimiter",&node);
		node->get_text(&bstr_fileDelimiter);
		element->selectSingleNode(L"Hash",&node);
		node->get_text(&bstr_hash);
		element->selectSingleNode(L"FileName",&node);
		node->get_text(&bstr_fileName);
		element->selectSingleNode(L"TagFile",&node);
		node->get_text(&bstr_tagFile);
		element->selectSingleNode(L"TagExtension",&node);
		node->get_text(&bstr_tagExtension);
	}
	catch(...)
	{
		delete [] fileParams;
		return NULL;
	}
	publicKeyStr = bstr_publicKey;
	privateKeyStr = bstr_privateKey;
	fileDelimiterStr = bstr_fileDelimiter;
	hashStr = bstr_hash;
	fileNameStr = bstr_fileName;
	tagExtensionStr = bstr_tagExtension;
	tagFileStr = bstr_tagFile;
	



	fileParams->publicKey = new char [publicKeyStr.GetLength()+1];
	fileParams->privateKey = new char [privateKeyStr.GetLength()+1];
	fileParams->fileName = new wchar_t [fileNameStr.GetLength()+1];


	ZeroMemory(fileParams->publicKey,publicKeyStr.GetLength()+1);
	ZeroMemory(fileParams->privateKey,privateKeyStr.GetLength()+1);
	ZeroMemory(fileParams->fileName,(fileNameStr.GetLength()*2)+1);

	char* binaryData = GetBinaryOfString(fileDelimiterStr.GetBuffer(),fileDelimiterStr.GetLength()+1,&binaryLength);
	fileParams->delimiter = new char [binaryLength];
	ZeroMemory(fileParams->delimiter,binaryLength);
	memcpy(fileParams->delimiter,binaryData,binaryLength);
	delete [] binaryData;

	binaryData = GetBinaryOfString(hashStr.GetBuffer(),hashStr.GetLength()+1,&binaryLength);
	fileParams->hash = new char [binaryLength];
	ZeroMemory(fileParams->hash,binaryLength);
	memcpy(fileParams->hash,binaryData,binaryLength);
	delete [] binaryData;

	binaryData = GetBinaryOfString(tagExtensionStr.GetBuffer(),tagExtensionStr.GetLength()+1,&binaryLength);
	fileParams->tagExtension = new char [binaryLength];
	ZeroMemory(fileParams->tagExtension,binaryLength);
	memcpy(fileParams->tagExtension,binaryData,binaryLength);
	delete [] binaryData;

	binaryData = GetBinaryOfString(tagFileStr.GetBuffer(),tagFileStr.GetLength()+1,&binaryLength);
	fileParams->tagFile = new char [binaryLength];
	ZeroMemory(fileParams->tagFile,binaryLength);
	memcpy(fileParams->tagFile,binaryData,binaryLength);
	delete [] binaryData;



	memcpy(fileParams->publicKey,publicKeyStr.GetBuffer(),publicKeyStr.GetLength()+1);
	memcpy(fileParams->privateKey,privateKeyStr.GetBuffer(),privateKeyStr.GetLength()+1);
	wcscpy(fileParams->fileName,fileNameStr);

	CoUninitialize();
	return fileParams;
}
bool KeyDataBaseAccess::CreateNewKeyDataBaseFile(bool usePassword,bool useHardwareSerial,unsigned char * key)
{
	unsigned char testData[FILE_TEST_PASS_DATA_LENGTH];
	ZeroMemory(testData,FILE_TEST_PASS_DATA_LENGTH);
	unsigned char encryptedTestData [ FILE_TEST_PASS_DATA_LENGTH];
	ZeroMemory(encryptedTestData,FILE_TEST_PASS_DATA_LENGTH);
	GenerateRandomBytes(testData,FILE_TEST_PASS_DATA_LENGTH);
	unsigned char realKey [SHA256_DIGEST_LENGTH];
	ZeroMemory(realKey,SHA256_DIGEST_LENGTH);
	bool success = false;
	unsigned char iv[16] = INITALIZATION_VECTOR;
	unsigned char tag[TAG_LEN];
	ofstream newDataBaseFile;
	//must delete data first 
	newDataBaseFile.open(DATABASE_KEY_FILE_NAME,ios::trunc);
	newDataBaseFile.close();
	
		
	if(usePassword)
	{
		char dataEntryIsPasswd = USE_ONLY_PASS;
		newDataBaseFile.open(DATABASE_KEY_FILE_NAME,ios::out | ios::binary | ios::app);
		newDataBaseFile.write(&dataEntryIsPasswd,FILE_FLAG_LENGTH);
		success = GenerateKeyDataBaseFilePasswd(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}
	else if(useHardwareSerial)
	{
		char dataEntryIsPasswd = USE_PASS_AND_HARDWARE;
		newDataBaseFile.open(DATABASE_KEY_FILE_NAME,ios::out | ios::binary | ios::app);
		newDataBaseFile.write(&dataEntryIsPasswd,FILE_FLAG_LENGTH);
		success = GenerateKeyDataBaseFilePasswdAndHardware(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}

	//encrypt data and place into file
	if(!success)
	{
		newDataBaseFile.close();
		return false;
	}
	int valEncrypt = Encrypt(testData,FILE_TEST_PASS_DATA_LENGTH,NULL,0,realKey,iv,encryptedTestData,tag);
	if(valEncrypt == -1)
	{
		newDataBaseFile.close();
		return false;
	}
	newDataBaseFile.write((char*)&tag[0],TAG_LEN);
	newDataBaseFile.write((char*)&encryptedTestData[0],FILE_TEST_PASS_DATA_LENGTH);
	newDataBaseFile.close();

	return true;
}
void KeyDataBaseAccess::ClearKeyDataBaseList()
{
	POSITION currentPos = keyDatabaseList.GetHeadPosition();
	while(currentPos != NULL)
	{
		ClearFileParams(keyDatabaseList.GetNext(currentPos));
	}
	keyDatabaseList.RemoveAll();
	return;
}
 CList<FileParameters*>* KeyDataBaseAccess::GetKeyDataBaseList(unsigned char * key)
 {
	FileParameters* fileParams;
	unsigned char iv [16] = INITALIZATION_VECTOR;
	//open file and do decrypt in stream find <FileParams> and </FileParams> can be found in chunk use 2 buffers
	__int64 numRead = 0;
	__int64 pos = FILE_FLAG_LENGTH+TAG_LEN+FILE_TEST_PASS_DATA_LENGTH;//set to this because first mu;itple bytes hold if it hold important information
	__int64 posStartOffset = FILE_FLAG_LENGTH+TAG_LEN+FILE_TEST_PASS_DATA_LENGTH;
	__int64 readAmount = 0;
	fstream inputFileEncrypted;
	inputFileEncrypted.open(DATABASE_KEY_FILE_NAME,ios::in | ios::binary);
	inputFileEncrypted.seekg (0, inputFileEncrypted.end);
	__int64 fileLength = inputFileEncrypted.tellg();
	if(fileLength == -1)
		return NULL;

	char flagVal = GetFlagFile();
	unsigned char realKey [SHA256_DIGEST_LENGTH];
	ZeroMemory(realKey,SHA256_DIGEST_LENGTH);
	bool success = false;
	if(flagVal == USE_PASS_AND_HARDWARE)
	{
		success = GenerateKeyDataBaseFilePasswdAndHardware(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}
	else if (flagVal == USE_ONLY_PASS)
	{
		success = GenerateKeyDataBaseFilePasswd(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));

	}
	if(!success)
		return false;
	char* beginTag = "<FileParams>";
	char* endTag = "</FileParams>";
	CStringA rawDecryptedInput = "";
	CStringA xmlInput = "";
	unsigned char* rawInputData = NULL;
	unsigned char* rawDecryptedData = NULL;
	unsigned char tag [TAG_LEN];
	long sizeToRead= 0;
	while(fileLength > pos)// -1 because starting 1 byte off
	{
		inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
		inputFileEncrypted.read((char*)&sizeToRead,LENGTH_XML_INDENIFER);
		pos += LENGTH_XML_INDENIFER;
		if((fileLength-pos) >= sizeToRead)
			readAmount = sizeToRead;
		else
			readAmount = fileLength-pos;
		if(fileLength != numRead-1)// we will only read 1 entry in at a time based on the length before hand
		{
			__int64 tempPos = pos;//do not mess with master pos
			__int64 dataAmount = readAmount-TAG_LEN;
			rawInputData = new unsigned char [readAmount];
			rawDecryptedData = new unsigned char [readAmount];
			ZeroMemory(rawInputData,readAmount);
			ZeroMemory(rawDecryptedData,readAmount);
			inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
			inputFileEncrypted.read((char *)&tag[0],TAG_LEN);
			tempPos += TAG_LEN;

			inputFileEncrypted.seekg(tempPos,inputFileEncrypted.beg);
			inputFileEncrypted.read((char *)&rawInputData[0],dataAmount);
			int valEncrypt = Decrypt(rawInputData,dataAmount,NULL,0,realKey,iv,rawDecryptedData,tag);
			if(valEncrypt == -1)
			{
				delete [] rawInputData;
				delete [] rawDecryptedData;
				inputFileEncrypted.close();
				return NULL;
			}
		}
		fileParams = GetFileParams((char*)rawDecryptedData);
		if(fileParams == NULL)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			inputFileEncrypted.close();
			return NULL;
		}
		if(fileLength != numRead-1)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			numRead += readAmount;
			pos += readAmount;
		}
		fileParams->keep = true;//default to true
		keyDatabaseList.AddTail(fileParams);
	}
	inputFileEncrypted.close();
	return &keyDatabaseList;
 }

 bool KeyDataBaseAccess::DeleteFileEntrys(unsigned char * key)
 {
	 FileParameters* fileParams;
	unsigned char iv [16] = INITALIZATION_VECTOR;
	//open file and do decrypt in stream find <FileParams> and </FileParams> can be found in chunk use 2 buffers
	__int64 numRead = 0;
	__int64 pos = FILE_FLAG_LENGTH+TAG_LEN+FILE_TEST_PASS_DATA_LENGTH;//set to this because first mu;itple bytes hold if it hold important information
	__int64 posHeaderData = 0;//header data is at the begining
	const __int64 headerDataAmount = FILE_FLAG_LENGTH+TAG_LEN+FILE_TEST_PASS_DATA_LENGTH;;
	__int64 readAmount = 0;
	fstream inputDataBase;
	fstream newDataBase;
	inputDataBase.open(DATABASE_KEY_FILE_NAME,ios::in | ios::binary);
	/* trunc the file then close cause you can not use append bit with trunc bit*/ 
	newDataBase.open(DATABASE_KEY_TEMP_FILE_NAME,ios::out | ios::binary | ios::trunc);
	newDataBase.close();
	/*********************************************************************************/
	newDataBase.open(DATABASE_KEY_TEMP_FILE_NAME,ios::out | ios::binary | ios::app);
	inputDataBase.seekg (0, inputDataBase.end);
	__int64 fileLength = inputDataBase.tellg();
	if(fileLength == -1)
		return NULL;

	char flagVal = GetFlagFile();
	unsigned char realKey [SHA256_DIGEST_LENGTH];
	ZeroMemory(realKey,SHA256_DIGEST_LENGTH);
	bool success = false;
	if(flagVal == USE_PASS_AND_HARDWARE)
	{
		success = GenerateKeyDataBaseFilePasswdAndHardware(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}
	else if (flagVal == USE_ONLY_PASS)
	{
		success = GenerateKeyDataBaseFilePasswd(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));

	}
	if(!success)
		return false;
	char* beginTag = "<FileParams>";
	char* endTag = "</FileParams>";
	CStringA rawDecryptedInput = "";
	CStringA xmlInput = "";
	unsigned char* rawInputData = NULL;
	unsigned char* rawDecryptedData = NULL;
	unsigned char tag [TAG_LEN];
	long sizeToRead= 0;
	__int64 dataAmount = 0;

	/* read in header data and write out to the temp file */
	char headerData[headerDataAmount];
	ZeroMemory(headerData,headerDataAmount);
	inputDataBase.seekg(posHeaderData,inputDataBase.beg);
	inputDataBase.read(headerData,headerDataAmount);
	newDataBase.write(headerData,headerDataAmount);
	/*******************************************************/
	while(fileLength > pos)// -1 because starting 1 byte off
	{
		inputDataBase.seekg(pos,inputDataBase.beg);
		inputDataBase.read((char*)&sizeToRead,LENGTH_XML_INDENIFER);
		pos += LENGTH_XML_INDENIFER;
		if((fileLength-pos) >= sizeToRead)
			readAmount = sizeToRead;
		else
			readAmount = fileLength-pos;
		if(fileLength != numRead-1)// we will only read 1 entry in at a time based on the length before hand
		{
			__int64 tempPos = pos;//do not mess with master pos
			dataAmount = readAmount-TAG_LEN;
			rawInputData = new unsigned char [readAmount];
			rawDecryptedData = new unsigned char [readAmount];
			ZeroMemory(rawInputData,readAmount);
			ZeroMemory(rawDecryptedData,readAmount);
			inputDataBase.seekg(pos,inputDataBase.beg);
			inputDataBase.read((char *)&tag[0],TAG_LEN);
			tempPos += TAG_LEN;

			inputDataBase.seekg(tempPos,inputDataBase.beg);
			inputDataBase.read((char *)&rawInputData[0],dataAmount);
			int valEncrypt = Decrypt(rawInputData,dataAmount,NULL,0,realKey,iv,rawDecryptedData,tag);
			if(valEncrypt == -1)
			{
				delete [] rawInputData;
				delete [] rawDecryptedData;
				inputDataBase.close();
				return NULL;
			}
		}
		fileParams = GetFileParams((char*)rawDecryptedData);
		if(fileParams == NULL)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			inputDataBase.close();
			newDataBase.close();
			return false;
		}
		else
		{
			POSITION posList = keyDatabaseList.GetHeadPosition();
			while(posList != NULL)
			{
				FileParameters* FileParamsListEntry = keyDatabaseList.GetNext(posList);
				if(CompareHash(FileParamsListEntry->hash,fileParams->hash))
				{
					if(FileParamsListEntry->keep)//use the one from the list
					{
						/* strucutre is total length then tag then data which is derived from total - tag */
						newDataBase.write((char*)&sizeToRead,LENGTH_XML_INDENIFER);

						newDataBase.write((char *)&tag[0],TAG_LEN);

						newDataBase.write((char *)&rawInputData[0],dataAmount);//write out the encrypted data we originally took
					}

				}
			}
			
		}
		if(fileLength != numRead-1)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			numRead += readAmount;
			pos += readAmount;
		}
	}
	inputDataBase.close();
	newDataBase.close();

	int sucess = remove(DATABASE_KEY_FILE_NAME);
	if(sucess)
		return false;
	success = rename(DATABASE_KEY_TEMP_FILE_NAME,DATABASE_KEY_FILE_NAME);
	if(sucess)
		return false;
	return true;
 }

FileParameters* KeyDataBaseAccess::GetFileEntry(wchar_t* filePathENCR,unsigned char* key)
{
	unsigned char fileInputhash [SHA256_DIGEST_LENGTH ];
	FileParameters* fileParams;
	ZeroMemory(fileInputhash,SHA256_DIGEST_LENGTH);
	bool fileFound = GetSHA256Hash(filePathENCR,fileInputhash);
	if(!fileFound)
		return false;
	unsigned char iv [16] = INITALIZATION_VECTOR;
	//open file and do decrypt in stream find <FileParams> and </FileParams> can be found in chunk use 2 buffers
	__int64 numRead = 0;
	__int64 pos = FILE_FLAG_LENGTH+TAG_LEN+FILE_TEST_PASS_DATA_LENGTH;//set to this because first mu;itple bytes hold if it hold important information
	__int64 posStartOffset = FILE_FLAG_LENGTH+TAG_LEN+FILE_TEST_PASS_DATA_LENGTH;
	__int64 readAmount = 0;
	fstream inputFileEncrypted;
	inputFileEncrypted.open(DATABASE_KEY_FILE_NAME,ios::in | ios::binary);
	inputFileEncrypted.seekg (0, inputFileEncrypted.end);
	__int64 fileLength = inputFileEncrypted.tellg();
	if(fileLength == -1)
		return NULL;

	char flagVal = GetFlagFile();
	unsigned char realKey [SHA256_DIGEST_LENGTH];
	ZeroMemory(realKey,SHA256_DIGEST_LENGTH);
	bool success = false;
	if(flagVal == USE_PASS_AND_HARDWARE)
	{
		success = GenerateKeyDataBaseFilePasswdAndHardware(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}
	else if (flagVal == USE_ONLY_PASS)
	{
		success = GenerateKeyDataBaseFilePasswd(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));

	}
	if(!success)
		return false;
	char* beginTag = "<FileParams>";
	char* endTag = "</FileParams>";
	CStringA rawDecryptedInput = "";
	CStringA xmlInput = "";
	unsigned char* rawInputData = NULL;
	unsigned char* rawDecryptedData = NULL;
	unsigned char tag [TAG_LEN];
	long sizeToRead= 0;
	while(fileLength != pos)// -1 because starting 1 byte off
	{
		inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
		inputFileEncrypted.read((char*)&sizeToRead,LENGTH_XML_INDENIFER);
		pos += LENGTH_XML_INDENIFER;
		if((fileLength-pos) >= sizeToRead)
			readAmount = sizeToRead;
		else
			readAmount = fileLength-pos;
		if(fileLength != numRead-1)// we will only read 1 entry in at a time based on the length before hand
		{
			__int64 tempPos = pos;//do not mess with master pos
			__int64 dataAmount = readAmount-TAG_LEN;
			rawInputData = new unsigned char [readAmount];
			rawDecryptedData = new unsigned char [readAmount];
			ZeroMemory(rawInputData,readAmount);
			ZeroMemory(rawDecryptedData,readAmount);
			inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
			inputFileEncrypted.read((char *)&tag[0],TAG_LEN);
			tempPos += TAG_LEN;

			inputFileEncrypted.seekg(tempPos,inputFileEncrypted.beg);
			inputFileEncrypted.read((char *)&rawInputData[0],dataAmount);
			int valEncrypt = Decrypt(rawInputData,dataAmount,NULL,0,realKey,iv,rawDecryptedData,tag);
			if(valEncrypt == -1)
			{
				delete [] rawInputData;
				delete [] rawDecryptedData;
				inputFileEncrypted.close();
				return NULL;
			}
		}
		fileParams = GetFileParams((char*)rawDecryptedData);

		if(CompareHash(fileParams->hash,(char*)fileInputhash) == true)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			inputFileEncrypted.close();
			return fileParams;
		}
		else
		{
			ClearFileParams(fileParams);
		}

		if(fileParams == NULL)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			inputFileEncrypted.close();
			return NULL;
		}
		
		if(fileLength != numRead-1)
		{
			delete [] rawInputData;
			delete [] rawDecryptedData;
			numRead += readAmount;
			pos += readAmount;
		}
	}
	return NULL;//never find maching return NULL
}

bool KeyDataBaseAccess::SetFileEntry(wchar_t* filePathENCR,char* publicKey, char* privateKey,char* delimiter, unsigned char* key,char* tagExtension,char* tagFile)
{
	unsigned char fileInputhash [SHA256_DIGEST_LENGTH ];
	bool success = false;
	bool fileFound = GetSHA256Hash(filePathENCR,fileInputhash);
	if(!fileFound)
		return false;
	char flagVal = GetFlagFile();
	unsigned char realKey [SHA256_DIGEST_LENGTH];
	ZeroMemory(realKey,SHA256_DIGEST_LENGTH);
	if(flagVal == USE_PASS_AND_HARDWARE)
	{
		success = GenerateKeyDataBaseFilePasswdAndHardware(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));
	}
	else if (flagVal == USE_ONLY_PASS)
	{
		success = GenerateKeyDataBaseFilePasswd(realKey,SHA256_DIGEST_LENGTH,key,strlen((char*)key));

	}
	if(!success)
		return false;
	CoInitialize(NULL);
	OleInitialize(NULL);
	MSXML2::IXMLDOMDocument2Ptr  doc;
	doc.CreateInstance(__uuidof(MSXML2::DOMDocument60));
	IXMLDOMElementPtr element;
	element.CreateInstance((__uuidof(MSXML2::IXMLDOMElementPtr)));
	IXMLDOMNodePtr node;
	node.CreateInstance((__uuidof(MSXML2::IXMLDOMNodePtr)));
	BSTR xmlTemplate = L"<FileParams> <PublicKey> </PublicKey> <PrivateKey> </PrivateKey> <FileDelimiter> </FileDelimiter> <Hash> </Hash> <FileName> </FileName> <TagExtension> </TagExtension> <TagFile> </TagFile> </FileParams>";
	CStringW tempAdd = L"";
	CStringA xmlInput = "";
	unsigned char tag [TAG_LEN];
	char* encodedData;
	try
	{
		doc->loadXML(xmlTemplate);
		element = doc->GetdocumentElement();
		element->selectSingleNode(L"PublicKey",&node);
		tempAdd = publicKey;
		node->put_text(tempAdd.GetBuffer());
		element->selectSingleNode(L"PrivateKey",&node);
		tempAdd = privateKey;
		node->put_text(tempAdd.GetBuffer());
		element->selectSingleNode(L"FileName",&node);
		tempAdd = filePathENCR;
		node->put_text(tempAdd.GetBuffer());
		element->selectSingleNode(L"FileDelimiter",&node);
		encodedData = GetStringOfBinary(delimiter,FILE_DELIMITER_SIZE);
		tempAdd = encodedData;
		node->put_text(tempAdd.GetBuffer());
		delete [] encodedData;
		element->selectSingleNode(L"TagExtension",&node);
		encodedData = GetStringOfBinary(tagExtension,TAG_LEN);
		tempAdd = encodedData;
		node->put_text(tempAdd.GetBuffer());
		delete [] encodedData;
		element->selectSingleNode(L"TagFile",&node);
		encodedData = GetStringOfBinary(tagFile,TAG_LEN);
		tempAdd = encodedData;
		node->put_text(tempAdd.GetBuffer());
		delete [] encodedData;
		element->selectSingleNode(L"Hash",&node);
		encodedData = GetStringOfBinary((char*)fileInputhash,SHA256_DIGEST_LENGTH);
		tempAdd = encodedData;
		node->put_text(tempAdd.GetBuffer());
		delete [] encodedData;
	}
	catch(...)
	{
		return false;
	}
	//generate string 2 add
	xmlInput = CW2A(doc->Getxml());
	unsigned char* encryptedData;
	unsigned char* plainTextData;
	unsigned char iv [16] = INITALIZATION_VECTOR;
	long bytesTotalData = xmlInput.GetLength()+1+TAG_LEN;
	long bytesXmlSize = xmlInput.GetLength()+1;
	plainTextData = new unsigned char [bytesXmlSize];
	encryptedData = new unsigned char [bytesXmlSize];
	ZeroMemory(plainTextData,bytesXmlSize);
	ZeroMemory(encryptedData,bytesXmlSize);
	memcpy(plainTextData,xmlInput.GetBuffer(),bytesXmlSize);
	fstream outputFileEncrypted;
	outputFileEncrypted.open(DATABASE_KEY_FILE_NAME,ios::out | ios::binary | ios::app);
	outputFileEncrypted.seekg (0, outputFileEncrypted.end);
	__int64 fileLength = outputFileEncrypted.tellg();
	if(fileLength == -1)
	{
		delete [] plainTextData;
		delete [] encryptedData;
		delete [] realKey;
		return NULL;
	}

	int valEncrypt = Encrypt(plainTextData,xmlInput.GetLength()+1,NULL,0,realKey,iv,encryptedData,tag);
	if(valEncrypt == -1)
	{
		delete [] plainTextData;
		delete [] encryptedData;
		delete [] realKey;
		return false;
	}
	outputFileEncrypted.write((char*)&bytesTotalData,LENGTH_XML_INDENIFER);//writing out the number of bytes it is
	outputFileEncrypted.write((char *)tag,TAG_LEN);
	outputFileEncrypted.write((char *)encryptedData,bytesXmlSize);
	outputFileEncrypted.close();
	delete [] plainTextData;
	delete [] encryptedData;
	return true;
}
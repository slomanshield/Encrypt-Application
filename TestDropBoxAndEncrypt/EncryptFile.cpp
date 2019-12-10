#include "stdafx.h"
#include "EncryptFile.h"


void FileEncrypt::handleErrors()
{
	unsigned long errCode;

    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
    }
    abort();
}

EVP_CIPHER_CTX * FileEncrypt::InitCipher(unsigned char *key, unsigned char *iv,bool encrypt,bool decrypt)
{
	EVP_CIPHER_CTX *ctx = NULL;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

	if(encrypt)
	{
		/* Initialise the encryption operation. */
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
			return NULL;
	
		/* Initialise key and IV */
		if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return NULL;
	}
	else if(decrypt)
	{
		/* Initialise the decryption operation. */
		if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
			return NULL;
		if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) return  NULL;
	}
	
	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		return NULL;
	return ctx;

}
int FileEncrypt::Encrypt(EVP_CIPHER_CTX * ctx,unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len,unsigned char *ciphertext,unsigned char* tag,bool update,bool final)
{

	int len = 0, ciphertext_len = 0;

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
		if(update)
		{
			if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
				return -1;
		}
		/* Finalise the encryption. Normally ciphertext bytes may be written at
		 * this stage, but this does not occur in GCM mode
		 */
		else if(final)
		{
			if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
				return -1;
			ciphertext_len += len;
			if(1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len)) return -1;
			ciphertext_len += len;

			/* Get the tag */
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
				return 0;

			/* Clean up */
			EVP_CIPHER_CTX_free(ctx);
		}
        ciphertext_len = len;
    }

    

    return ciphertext_len;

}

int FileEncrypt::Decrypt(EVP_CIPHER_CTX * ctx,unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,//no point for aad
            int aad_len,unsigned char *plaintext,unsigned char* tag,bool update,bool final)
{

	
    int len = 0, plaintext_len = 0, ret;
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
		if(update)
		{
			if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
				return -1;
			plaintext_len += len;

		}
		else if(final)
		{
			if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
				return -1;
			plaintext_len += len;
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
    }

}

HardwareIds FileEncrypt::GetHardWareIds()
{
	CoInitialize(NULL);
	OleInitialize(NULL);
	HRESULT hr;
	USES_CONVERSION;

	HardwareIds hardwareIds;
	hardwareIds.cpu = NULL;
	hardwareIds.hardDrive = NULL;
	VARIANT vtData;
	ULONG uReturn = 0;
	CStringW serialNumber = L"";
	CStringA serialNumberA = ""; 
	IWbemClassObject *pclsObj;

	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemServices * pWbemServices = NULL;
	IWbemLocator * pIWbemLocator = NULL;

	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pIWbemLocator);
	if(FAILED(hr))
		return hardwareIds;
	hr = pIWbemLocator->ConnectServer(//connect to local root machine
		BSTR(L"ROOT\\CIMV2"), 
		NULL, NULL, 0, NULL, 0, 0, &pWbemServices);
	if(FAILED(hr))
		return hardwareIds;
	hr = CoSetProxyBlanket(pWbemServices,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);
	if(FAILED(hr))
		return hardwareIds;
	hr = pWbemServices->ExecQuery(L"WQL",L"SELECT * FROM Win32_DiskDrive  ",WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if(FAILED(hr))
		return hardwareIds;
	
	hr = pEnumerator->Next(WBEM_INFINITE, 1,&pclsObj,&uReturn);
	if(0 == uReturn)
	{
		return hardwareIds;
	}
	pclsObj->Get(L"SerialNumber",0,&vtData,0,0); // using first hard drive
	pclsObj->Release();
	 serialNumber = vtData.bstrVal;
	 serialNumberA = W2A(serialNumber);
	hardwareIds.hardDrive = new char [9];
	ZeroMemory(hardwareIds.hardDrive,9);
	srand (time(NULL));//seed time to pick random spots out the serial id
	for(int i = 0 ;i < 8;i++)
	{
		hardwareIds.hardDrive[i] = serialNumberA.GetAt(rand() % serialNumberA.GetLength());
	}
	pEnumerator->Release();

	hr = pWbemServices->ExecQuery(L"WQL",L"SELECT * FROM Win32_Processor  ",WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if(FAILED(hr))
		return hardwareIds;
	hr = pEnumerator->Next(WBEM_INFINITE, 1,&pclsObj,&uReturn);
	if(0 == uReturn)
	{
		return hardwareIds;
	}
	pclsObj->Get(L"ProcessorId",0,&vtData,0,0); // using first cpu
	pclsObj->Release();
	serialNumber = vtData.bstrVal;
	serialNumberA = W2A(serialNumber);
	hardwareIds.cpu = new char [9];
	ZeroMemory(hardwareIds.cpu,9);
	srand (time(NULL));//seed time to pick random spots out the serial id
	for(int i = 0 ;i < 8;i++)
	{
		hardwareIds.cpu[i] = serialNumberA.GetAt(rand() % serialNumberA.GetLength());
	}
	pEnumerator->Release();
	pIWbemLocator->Release();
	pWbemServices->Release();
	CoUninitialize();
	return hardwareIds;
}

bool FileEncrypt::GenerateAESKey(unsigned char* buffer,long size)
{
	srand (time(NULL));
	char sudoTimeBytes[9];
	ZeroMemory(sudoTimeBytes,9);
	char xoredTimeBytes[9];
	ZeroMemory(xoredTimeBytes,9);
	char fileInputhash [SHA256_DIGEST_LENGTH];
	ZeroMemory(fileInputhash,SHA256_DIGEST_LENGTH);
	for(int i = 0; i < 8; i++)
	{
		sudoTimeBytes[i] = rand() % 256; //store first half
	}

	for(int i = 0;i < 8;i++)
	{
		xoredTimeBytes[i] = rand() % 256;//get second half
	}

	for(int i = 0 ;i < 8 ;i++)
	{
		xoredTimeBytes[i] = sudoTimeBytes[i] ^ xoredTimeBytes[i];//store the xor of second half time
	}

	//  now get hardwareserial Ids
	HardwareIds hardwareIds  = GetHardWareIds();//gets random string of 8 byte each of hardware ID using first cpu and hard drive
	if(hardwareIds.cpu == NULL || hardwareIds.hardDrive == NULL)
		return false;

	memcpy(&fileInputhash[0],&sudoTimeBytes[0],8);
	memcpy(&fileInputhash[8],&xoredTimeBytes[0],8);
	memcpy(&fileInputhash[16],&hardwareIds.cpu[0],8);
	memcpy(&fileInputhash[24],&hardwareIds.hardDrive[0],8);
	// create hash 
	SHA256_CTX mdContext;
	SHA256_Init (&mdContext);
	SHA256_Update (&mdContext,&fileInputhash[0], SHA256_DIGEST_LENGTH);
	SHA256_Final (buffer,&mdContext);
	return true;
}

char* FileEncrypt::GenerateDelimiter()
{
	srand (time(NULL));
	char * delimiter = new char [FILE_DELIMITER_SIZE+1];
	ZeroMemory(delimiter,FILE_DELIMITER_SIZE+1);
	try
	{
		for(long i =0;i < FILE_DELIMITER_SIZE;i++)
		{
			delimiter[i] = rand() % 256 + 1;
		}

	}
	catch(...)
	{
		return NULL;
	}
	return delimiter;


}

void FileEncrypt::ClearKeyPairs(Public_Private_Key keyPairs)
{
	try
	{
		free(keyPairs.privateKey);
		free(keyPairs.publicKey);
	}
	catch(...)
	{
		return;
	}
}


Public_Private_Key FileEncrypt::GeneratePublicPrivateKey(int bits)
{
	Public_Private_Key keyPairs;
	keyPairs.privateKey = NULL;
	keyPairs.publicKey = NULL;
	RSA* rsa;
	rsa = RSA_new();
	BIGNUM e;
	e.d = new unsigned int [1];//use hardware ids to set expoenent
	e.d[0] = 65535;
	e.top = 1+1;//+1 to the size of array
	e.flags = 0;
	e.neg = 0;
	e.dmax = 1;
	RSA_generate_key_ex(rsa,bits,&e,NULL);
	if(rsa == 0)
		return keyPairs;
	BIO *bioPrivate = BIO_new(BIO_s_mem());
	BIO *bioPublic = BIO_new(BIO_s_mem());
	if(PEM_write_bio_RSAPrivateKey(bioPrivate, rsa, NULL, NULL, 0, NULL, NULL) != 1)
		return keyPairs;
	if(PEM_write_bio_RSAPublicKey(bioPublic, rsa) != 1)
		return keyPairs;

	int keylenPublic;
	int keyLenPrivate;
	keylenPublic = BIO_pending(bioPublic);
	keyLenPrivate = BIO_pending(bioPrivate);
	keyPairs.publicKey = (char *)malloc(keylenPublic+1);
	keyPairs.privateKey = (char *)malloc(keyLenPrivate+1);
	ZeroMemory(keyPairs.publicKey,keylenPublic+1);
	ZeroMemory(keyPairs.privateKey,keyLenPrivate+1);
	try{
		BIO_read(bioPrivate, keyPairs.privateKey, keyLenPrivate);
		BIO_read(bioPublic, keyPairs.publicKey, keylenPublic);
	}
	catch(...)
	{
		free(keyPairs.privateKey);
		keyPairs.privateKey = NULL;
		free(keyPairs.publicKey);
		keyPairs.publicKey = NULL;
		RSA_free(rsa);
		delete [] e.d;
		return keyPairs;
	}
	RSA_free(rsa);
	BIO_free(bioPrivate);
	BIO_free(bioPublic);
	delete [] e.d;
	return keyPairs;
}
RSA* FileEncrypt::GetRSADataFromPlainTextKey(char* plainTextKey,bool public_private)
{
	RSA* rsa = RSA_new();
	BIO *keybio =  BIO_new_mem_buf(plainTextKey,-1);
	if (keybio==NULL)
    {
		return NULL;
	}
	if(public_private)
	{
		 rsa = PEM_read_bio_RSAPublicKey(keybio,&rsa,NULL,NULL);
	}
	else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
		char * error  =ERR_error_string(ERR_peek_last_error(),NULL);
    }
    if(rsa == NULL)
		return NULL;
	BIO_free(keybio);
	return rsa;
}
EncryptedFileData FileEncrypt::FindKeyStart(wchar_t* filePath,char* delimiter,Public_Private_Key keypairs,unsigned char* tag)
{
	__int64 numRead = 0;
	__int64 pos = 0;
	__int64 readAmount = 0;
	__int64 startDelimiter = 0;
	int delimiterCharLocation = 0;
	bool startFound = false;
	EncryptedFileData fileData;
	fstream inputFileEncrypted;
	inputFileEncrypted.open(filePath,ios::in | ios::binary);
	inputFileEncrypted.seekg (0, inputFileEncrypted.end);
	__int64 fileLength = inputFileEncrypted.tellg();
	if(fileLength == -1)
	{
		fileData.startDelimiter = -1;
		return fileData;
	}
	unsigned char* encryptedData;
	unsigned char* encryptedExtension;
	unsigned char* plainTextExtension;
	unsigned char* encryptedKey;
	unsigned char* plaintextAesKey;
	unsigned char iv [16] = IV;
	while(fileLength != numRead)
	{
		if((fileLength-pos) >= MAX_FILE_READ_SIZE)
			readAmount = MAX_FILE_READ_SIZE;
		else
			readAmount = fileLength-pos;
		encryptedData = new unsigned char [readAmount];
		ZeroMemory(encryptedData,readAmount);
		inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
		inputFileEncrypted.read((char *)&encryptedData[0],readAmount);
		for(int i =0;i < readAmount;i++)
		{
			if(delimiterCharLocation == FILE_DELIMITER_SIZE)
			{
				startFound = true;
				break;
			}
			if(encryptedData[i] == (unsigned char)delimiter[delimiterCharLocation])
			{
				if(delimiterCharLocation == 0)
				{
					startDelimiter = pos+i;
					delimiterCharLocation++;
				}
				else
					delimiterCharLocation++;
			}
			else
				delimiterCharLocation = 0;

		}
		delete [] encryptedData;
		numRead += readAmount;
		pos += readAmount;
		if(startFound)
			break;
	}
	//read in file extension
	pos = startDelimiter+64;
	encryptedKey = new unsigned char [RSA_DATA_SIZE];
	ZeroMemory(encryptedKey,RSA_DATA_SIZE);
	inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
	inputFileEncrypted.read((char *)&encryptedKey[0],RSA_DATA_SIZE);
	plaintextAesKey =  new unsigned  char [32];
	bool successDecrypt = DecryptKeyPP(encryptedKey,plaintextAesKey,keypairs);
	delete [] encryptedKey;
	if(!successDecrypt)
	{
		delete [] plaintextAesKey;
		fileData.startDelimiter = -1;
		return fileData;
	}
	fileData.key = plaintextAesKey;
	pos = startDelimiter+64+RSA_DATA_SIZE;

	int extensionLength = fileLength-pos;
	inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
	encryptedExtension = new unsigned char[extensionLength];
	plainTextExtension = new unsigned char[extensionLength];

	ZeroMemory(plainTextExtension,extensionLength);
	ZeroMemory(encryptedExtension,extensionLength);
	inputFileEncrypted.read((char *)&encryptedExtension[0],extensionLength);

	EVP_CIPHER_CTX * ctx = InitCipher(plaintextAesKey,iv,false,true);
	int valDecrypt = Decrypt(ctx,encryptedExtension,extensionLength,NULL,0,plainTextExtension,tag,false,true);
	if(valDecrypt == -1)
	{
		delete [] encryptedExtension;
		delete [] plainTextExtension;
		delete [] plaintextAesKey;
		fileData.startDelimiter = -1;
		return fileData;
	}
	fileData.fileExtension = plainTextExtension;
	delete [] encryptedExtension;
	delete [] plainTextExtension;
	inputFileEncrypted.close();
	fileData.startDelimiter = startDelimiter;
	return fileData;
}

bool FileEncrypt::EncryptKeyPP(unsigned char* plaintextKeyAes,unsigned char* encryptedKeyRSA,Public_Private_Key keypairs)//for 4096 bit key max can be 512 but use 214 bytes,since AES key it is always 32 bytes
{
	const int publicKeyLength = strlen(keypairs.publicKey);
	//char* publicKeyPrev;
	RSA* rsa;
	/*char publicKey [publicKeyLength];//need this because it gets destroyed after encryption
	ZeroMemory(publicKey,publicKeyLength);
	memcpy(publicKey,keypairs.publicKey,publicKeyLength);*/
	//publicKeyPrev = publicKey;
	rsa = GetRSADataFromPlainTextKey(keypairs.publicKey,true);
	int val = RSA_size(rsa);
	//encryptedKeyRSA = new  unsigned char [RSA_size(rsa)];
	
	int encrypt_len = RSA_public_encrypt(32,plaintextKeyAes,encryptedKeyRSA,rsa,RSA_PKCS1_OAEP_PADDING);//always 32 because AES key length
	if(encrypt_len == -1)
	{
		//delete [] publicKey;
		RSA_free(rsa);
		return false;
	}
	//delete [] publicKey;
	RSA_free(rsa);
	return true;
	//must delete encryptedKeyRSA after writing to file
}

bool FileEncrypt::DecryptKeyPP(unsigned char* encryptedKeyRSA,unsigned char* plaintextAes,Public_Private_Key keypairs)
{
	int privateKeyLength = strlen(keypairs.privateKey);
	char* privateKey;//need this because it gets destroyed after encryption
	//char* privateKeyPrev;
	RSA* rsa;
	privateKey = new char[privateKeyLength];
	ZeroMemory(privateKey,privateKeyLength);
	memcpy(privateKey,keypairs.privateKey,privateKeyLength);
	//publicKeyPrev = publicKey;
	rsa = GetRSADataFromPlainTextKey(privateKey,false);
	int val = RSA_size(rsa);
	//plaintextAes = new unsigned char [32];
	ZeroMemory(plaintextAes,32);
	int decrypt_len = RSA_private_decrypt(RSA_DATA_SIZE,encryptedKeyRSA,plaintextAes,rsa,RSA_PKCS1_OAEP_PADDING);
	if(decrypt_len == -1)
	{
		delete [] privateKey;
		RSA_free(rsa);
		return false;
	}
	RSA_free(rsa);
	delete [] privateKey;
	return true;
}

bool FileEncrypt::EncryptFile(wchar_t* filePath,char* delimiter,Public_Private_Key keypairs,unsigned char* tagExtension,unsigned char* tagFile)
{
	USES_CONVERSION;
	__int64 numRead = 0;
	__int64 pos = 0;
	__int64 readAmount = 0;
	bool finalBytes = false;
	unsigned char key [32];
	GenerateAESKey(key,32);
	unsigned char iv [16] = IV;
	fstream outPutFileEncrypted;
	fstream inputFilePlainText;
	CStringW newFile = filePath;
	CStringW oldFile = filePath;
	newFile = newFile.Mid(0,newFile.Find(L"."));
	newFile.Append(L".encr");
	outPutFileEncrypted.open(newFile.GetBuffer(),ios::out | ios::binary | ios::trunc);
	inputFilePlainText.open(filePath,ios::in | ios::binary);
	inputFilePlainText.seekg (0, inputFilePlainText.end);
	__int64 fileLength = inputFilePlainText.tellg();
	if(fileLength == -1)
		return false;
	unsigned char* plainTextData;
	unsigned char* encryptedData;
	unsigned char* encryptedAesKeyPP;
	EVP_CIPHER_CTX * ctx = InitCipher(key,iv,true,false);
	if(ctx == NULL)
		return false;
	while(fileLength != numRead)
	{
		if((fileLength-pos) >= MAX_FILE_READ_SIZE)
			readAmount = MAX_FILE_READ_SIZE;
		else
		{
			finalBytes = true;
			readAmount = fileLength-pos;
		}
		plainTextData = new unsigned char [readAmount];
		ZeroMemory(plainTextData,readAmount);
		encryptedData = new unsigned char [readAmount];
		ZeroMemory(encryptedData,readAmount);
		inputFilePlainText.seekg(pos,inputFilePlainText.beg);
		inputFilePlainText.read((char *)&plainTextData[0],readAmount);
		int valEncrypt = 0;

		if(finalBytes)
			valEncrypt = Encrypt(ctx,plainTextData,readAmount,NULL,0,encryptedData,tagFile,false,true);
		else
			valEncrypt = Encrypt(ctx,plainTextData,readAmount,NULL,0,encryptedData,tagFile,true,false);
		if(valEncrypt == -1)
			return false;
		outPutFileEncrypted.seekg(pos,inputFilePlainText.beg);
		outPutFileEncrypted.write((char *)&encryptedData[0],readAmount);
		delete [] plainTextData;
		delete [] encryptedData;
		numRead += readAmount;
		pos += readAmount;
	}
	inputFilePlainText.close();
	outPutFileEncrypted.close();//open the file again for append makes things easier :33

	outPutFileEncrypted.open(newFile.GetBuffer(),ios::out | ios::binary | ios::app);
	outPutFileEncrypted.write(delimiter,FILE_DELIMITER_SIZE);
	encryptedAesKeyPP = new unsigned char [RSA_DATA_SIZE];

	bool successRsaEncrypt = EncryptKeyPP(key,encryptedAesKeyPP,keypairs);
	if(!successRsaEncrypt)
	{
		delete [] encryptedAesKeyPP;
		return false;
	}
	outPutFileEncrypted.write((char *)encryptedAesKeyPP,RSA_DATA_SIZE);
	delete [] encryptedAesKeyPP;
	CStringA originalFileExtension = W2A(oldFile.Mid(oldFile.Find(L".")+1).GetBuffer());

	char* plainTextFileExtension = new char [originalFileExtension.GetLength()+1];
	char* encryptedFileExtension = new char [originalFileExtension.GetLength()+1];

	ZeroMemory(plainTextFileExtension,originalFileExtension.GetLength()+1);
	ZeroMemory(encryptedFileExtension,originalFileExtension.GetLength()+1);

	memcpy(plainTextFileExtension,originalFileExtension,originalFileExtension.GetLength()+1);

	ctx = InitCipher(key,iv,true,false);

	int valEncrypt = Encrypt(ctx,(unsigned char*)plainTextFileExtension,originalFileExtension.GetLength()+1,NULL,0,(unsigned char*)encryptedFileExtension,tagExtension,false,true);
	if(valEncrypt == -1)
		return false;

	outPutFileEncrypted.write(encryptedFileExtension,originalFileExtension.GetLength()+1);
	
	outPutFileEncrypted.close();

	delete [] plainTextFileExtension;
	delete [] encryptedFileExtension;
	

	return true;
}

bool FileEncrypt::DecryptFile(wchar_t* filePath,char* delimiter,Public_Private_Key keypairs,unsigned char* tagExtension,unsigned char* tagFile)
{
	USES_CONVERSION;
	EncryptedFileData data = FindKeyStart(filePath,delimiter, keypairs,tagExtension);
	if(data.startDelimiter == -1)
		return false;
	__int64 numRead = 0;
	__int64 pos = 0;
	__int64 readAmount = 0;
	bool finalBytes = false;
	CStringW newFile = filePath;
	newFile = newFile.Mid(0,newFile.Find(L"."));
	newFile.Append(A2W('.'+data.fileExtension));
	unsigned char iv [16] = IV;
	fstream inputFileEncrypted;
	fstream outputFilePlainText;
	outputFilePlainText.open(newFile.GetBuffer(),ios::out | ios::binary | ios::trunc);
	inputFileEncrypted.open(filePath,ios::in | ios::binary);
	unsigned char* plainTextData;
	unsigned char* encryptedData;
	EVP_CIPHER_CTX * ctx = InitCipher(data.key,iv,false,true);
	while(data.startDelimiter != numRead)
	{
		if((data.startDelimiter-pos) >= MAX_FILE_READ_SIZE)
			readAmount = MAX_FILE_READ_SIZE;
		else
		{
			finalBytes = true;
			readAmount = data.startDelimiter-pos;
		}
		plainTextData = new unsigned char [readAmount];
		ZeroMemory(plainTextData,readAmount);
		encryptedData = new unsigned char [readAmount];
		ZeroMemory(encryptedData,readAmount);
		inputFileEncrypted.seekg(pos,inputFileEncrypted.beg);
		inputFileEncrypted.read((char *)&encryptedData[0],readAmount);
		int valEncrypt = 0;


		if(finalBytes)
			valEncrypt = Decrypt(ctx,encryptedData,readAmount,NULL,0,plainTextData,tagFile,false,true);
		else
			valEncrypt = Decrypt(ctx,encryptedData,readAmount,NULL,0,plainTextData,tagFile,true,false);
		if(valEncrypt == -1)
		{
			outputFilePlainText.close();
			inputFileEncrypted.close();
			delete [] data.key;
			delete [] plainTextData;
			delete [] encryptedData;
			return false;
		}
		outputFilePlainText.seekg(pos,outputFilePlainText.beg);
		outputFilePlainText.write((char *)&plainTextData[0],readAmount);
		delete [] plainTextData;
		delete [] encryptedData;
		numRead += readAmount;
		pos += readAmount;
	}
	delete [] data.key;
	outputFilePlainText.close();
	inputFileEncrypted.close();\
	return true;
}


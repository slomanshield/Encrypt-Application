// TestDropBoxAndEncrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DropBoxApi.h"
#include "TestDropBoxAndEncrypt.h"
#include "KeyDataBaseAccess.h"
#include "EncryptFile.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// The one and only application object

CWinApp theApp;

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{ 
	KeyDataBaseAccess dataBaseAccess;
	//dataBaseAccess.CreateNewKeyDataBaseFile(false,true,(unsigned char *)"cooldog1");
	bool val = dataBaseAccess.CheckPasswd((unsigned char *)"cooldog1");
	//CList<FileParameters*>* fileEntryList = dataBaseAccess.GetKeyDataBaseList((unsigned char *) "cooldog1");
	//dataBaseAccess.ClearKeyDataBaseList();
	//dataBaseAccess.DeleteFileEntrys((unsigned char *) "cooldog1");
	FileEncrypt encryptHandler;
	Public_Private_Key keypairs = encryptHandler.GeneratePublicPrivateKey(RSA_KEY_SIZE);
	char* delimiter = encryptHandler.GenerateDelimiter();//must delete delimiter
	char tagExtension [TAG_LEN];
	char tagFile [TAG_LEN];
	encryptHandler.EncryptFile(L"C:\\Get Started with Dropbox.pdf",delimiter,keypairs,(unsigned char*)tagExtension,(unsigned char*)tagFile);
	//enter into database
	dataBaseAccess.SetFileEntry(L"C:\\Get Started with Dropbox.encr",keypairs.publicKey,keypairs.privateKey,delimiter,(unsigned char *)"cooldog1",tagExtension,tagFile);//get password from keyboard if nessecary
	// free keys after entry
	encryptHandler.ClearKeyPairs(keypairs);
	FileParameters* fileParams = dataBaseAccess.GetFileEntry(L"C:\\Get Started with Dropbox.encr",(unsigned char *)"cooldog1"); // must delete file params char pointers
	keypairs.publicKey = fileParams->publicKey;
	keypairs.privateKey = fileParams->privateKey;
	encryptHandler.DecryptFile(L"C:\\Get Started with Dropbox.encr",fileParams->delimiter,keypairs,(unsigned char*)fileParams->tagExtension,(unsigned char*)fileParams->tagFile);
	dataBaseAccess.ClearFileParams(fileParams);
	delete [] delimiter;
	int nRetCode = 0;
	DropBoxApi test = DropBoxApi();
	test.LoadAuthorizePage();
	CStringA code;
	char inputBuffer [200];
	memset(inputBuffer,0,200);
	cout << "Enter In Code From Webpage";
	while(strlen(inputBuffer) == 0)
	{
		cin >> inputBuffer;
	}
	code = inputBuffer;
	test.AuthorizeUser(code.GetBuffer());
	file_folders testFileFolder;
	testFileFolder.isFile = false;
	testFileFolder.isFolder = true;
	testFileFolder.path = "";//make it empty to query root
	CList<file_folders,file_folders&>* directoryItems = test.ListFolderAndFiles(testFileFolder);
	POSITION pos;
	file_folders tempInfo;
	pos = directoryItems->GetHeadPosition();
	/*while(pos != NULL)
	{
		tempInfo = directoryItems->GetNext(pos);
		if(tempInfo.path.Find("casperjs") > -1)
			test.ListFolderAndFiles(tempInfo);
	}
	test.UploadFile("/testUploadBig.mkv",L"C:\\testUploadBig.mkv");
	//test.DownloadFile("/testUploadBig.mkv",L"C:\\testUploadBig.mkv");
	return 1;*/
}

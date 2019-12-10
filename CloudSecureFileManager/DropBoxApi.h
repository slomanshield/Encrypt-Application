#include <winhttp.h>
#include "rapidjson\document.h"
#include "rapidjson\writer.h"
#include "rapidjson\stringbuffer.h"
#include "rapidjson\encodings.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdio.h>

#pragma comment(lib,"winhttp.lib")
#define MAX_FILE_CHUNK_SIZE 3000000
using namespace std;
using namespace rapidjson;
#define OAUTH_2_PARAM_GET_TOKEN L"/1/oauth2/token?"
#define API_LIST_FOLDER L"/2/files/list_folder"
#define API_LIST_FOLDER_CONTINUE L"/2/files/list_folder/continue"
#define API_UPLOAD_SESSION_START L"/2/files/upload_session/start"
#define API_UPLOAD_SESSION_APPEND L"/2/files/upload_session/append"
#define API_UPLOAD_SESSION_FINISH L"/2/files/upload_session/finish"
#define API_DOWNLOAD_SESSION L"/2/files/download"
#define GET_METADATA L"/2/files/get_metadata"
#define API_URI L"api.dropbox.com"
#define API_CONTENT_URI L"content.dropboxapi.com"
#define ACCEPT_APP_URI L"https://www.dropbox.com/1/oauth2/authorize?"
#define PROGRAM_NAME L"HardwareSecureCloudFileManager"
#define CONTENT_HEADER L"Content-Type: application/json"
#define CONTENT_UPLOAD_HEADER L"Content-Type: application/octet-stream"

#define APP_KEY L"ba22agzk8hhk19n"
#define APP_SECRET_KEY L"kriiobkfq208d23"
#define UNIQUE_ID L"sdafkj4ioe4rt"

struct file_folders
{
	CStringA path;
	CStringA name;
	bool isFile;
	bool isFolder;
};
class DropBoxApi
{
	private:
	
	public:
		DropBoxApi();
		void LoadAuthorizePage();
		bool AuthorizeUser(char * code);
		bool UploadFile(char* pathDropBox,wchar_t* pathLocalHost);
		bool DownloadFile(char* pathDropBox,wchar_t* pathLocalHost);
		void clearAllSessions();
		CList<file_folders,file_folders&>* ListFolderAndFiles(file_folders path);
	private:
			HANDLE  hRequestAuth; // only used for Auth
			HANDLE  hSessionApi,hConnectApi,hRequestApi; // used for directory traversal and download/upload
			CStringA oauth_token_access;// for api calls
			CStringA oauth_uid;
			CStringW oauth_Header_api;
			bool AddEntries(Document* entryDoc);
			bool UploadChunck(std::string data,wchar_t * uploadParams,bool finish);
			CList<file_folders,file_folders&> List_FoldersAndFiles;
};

#include "stdafx.h"
#include "DropBoxApi.h"


DropBoxApi::DropBoxApi()
{
	oauth_token_access = "";
	oauth_uid = "";
	hSessionApi = NULL;
	hConnectApi = NULL;
	hRequestApi = NULL;
}
void DropBoxApi::clearAllSessions()
{
	WinHttpCloseHandle(hRequestAuth);
	WinHttpCloseHandle(hSessionApi);
	WinHttpCloseHandle(hConnectApi);
	WinHttpCloseHandle(hRequestApi);
}
bool DropBoxApi::UploadChunck(std::string data,wchar_t * uploadParams,bool finishUpload)
{
	USES_CONVERSION;
	Document doc;
	char buffer [10000];
	memset(buffer,0,10000);
	DWORD dwSize;
	DWORD dwDownloaded;
	int error;
	bool bSuccess;
	if(hConnectApi)
	{
		if(finishUpload)
			hRequestApi = WinHttpOpenRequest( hConnectApi, L"POST",API_UPLOAD_SESSION_FINISH,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
		else
			hRequestApi = WinHttpOpenRequest( hConnectApi, L"POST",API_UPLOAD_SESSION_APPEND,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
		error = GetLastError();
	}
	if(hRequestApi)
	{
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,oauth_Header_api.GetBuffer(),wcslen(oauth_Header_api.GetBuffer()),WINHTTP_ADDREQ_FLAG_ADD );
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,CONTENT_UPLOAD_HEADER,wcslen(CONTENT_UPLOAD_HEADER),WINHTTP_ADDREQ_FLAG_ADD );
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,uploadParams,wcslen(uploadParams),WINHTTP_ADDREQ_FLAG_ADD);
		error = GetLastError();
		bSuccess = WinHttpSendRequest( hRequestApi,WINHTTP_NO_ADDITIONAL_HEADERS,0,(void *)data.data(),data.length(),data.length(),0);
	}
	if(bSuccess)
		bSuccess = WinHttpReceiveResponse( hRequestApi, NULL);
	WinHttpQueryDataAvailable( hRequestApi, &dwSize );
	if(dwSize == 0)
		return false;
	WinHttpReadData( hRequestApi,buffer, dwSize, &dwDownloaded );
	if(dwDownloaded == 0)
		return false;
	if(strlen(buffer) > 4)
	{
		doc.Parse(buffer);
		memset(buffer,0,10000);
		if(doc.HasMember("error_summary"))
			bSuccess =  false;
	}
	WinHttpCloseHandle(hRequestApi);
	hRequestApi = NULL;
	return bSuccess;
}
bool DropBoxApi::AddEntries(Document* entryDoc)
{
	file_folders tempInfo;
	CStringA _tag;
	try
	{
		if(!entryDoc->HasMember("entries"))
			return false;
		const Value& entryArray = entryDoc->operator[]("entries");
		for(rapidjson::SizeType i = 0; i < entryArray.Size(); i++)
		{
			 const Value& entryVal = entryArray[i];
			 _tag = entryVal[".tag"].GetString();
			 if(_tag.CompareNoCase("file") == 0)
			 {
				 tempInfo.isFile = true;
				 tempInfo.isFolder = false;
			 }
			 else if(_tag.CompareNoCase("folder") == 0)
			 {
				 tempInfo.isFile = false;
				 tempInfo.isFolder = true;
			 }
			 tempInfo.name = entryVal["name"].GetString();
			 tempInfo.path = entryVal["path_lower"].GetString();
			 List_FoldersAndFiles.AddTail(tempInfo);
		}
	}
	catch(...)
	{
		return false;
	}
	return true;
}
void DropBoxApi::LoadAuthorizePage()
{
	CStringW url = ACCEPT_APP_URI;
	url.Format(url+L"response_type=code&client_id=%s&state=%s&force_reapprove=false&disable_signup=false",APP_KEY,UNIQUE_ID);
	ShellExecute(0, 0, url.GetBuffer(), 0, 0 , SW_SHOW ); // open browser to send user to accept app
}
bool DropBoxApi::AuthorizeUser(char * code)
{
	if(strlen(code) == 0)
		return false;
	USES_CONVERSION;
	oauth_token_access = "";
	oauth_uid = "";
	bool bSuccess = false;
	int error;
	CStringA urlParams;
	CStringW params = OAUTH_2_PARAM_GET_TOKEN;
	hSessionApi = WinHttpOpen( PROGRAM_NAME,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
	if(hSessionApi)
	{
		 hConnectApi = WinHttpConnect( hSessionApi, API_URI,443, 0 );
	}
	if(hConnectApi)
	{
		params.Format(params+L"code=%s&grant_type=authorization_code&client_id=%s&client_secret=%s",A2W(code),APP_KEY,APP_SECRET_KEY);
		hRequestAuth = WinHttpOpenRequest( hConnectApi, L"POST", params.GetBuffer(),NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
	}
	if(hRequestAuth)
	{
		bSuccess = WinHttpSendRequest( hRequestAuth,WINHTTP_NO_ADDITIONAL_HEADERS,0,0,0,0,0);
	}
	if(bSuccess)
		bSuccess = WinHttpReceiveResponse( hRequestAuth, NULL);
	CStringA jsonResponse = "";
	if(bSuccess)
	{
		char buffer[10000];
		memset(buffer,0,10000);
		DWORD dwSize = 0;
		DWORD dwDownloaded= 0;
		do 
		{
			dwSize = 0;
			bSuccess = WinHttpQueryDataAvailable( hRequestAuth, &dwSize );
			error = GetLastError();
			if (!dwSize)
				break;
			if(!bSuccess){
				break;
			}
			bSuccess = WinHttpReadData( hRequestAuth,buffer, dwSize, &dwDownloaded );
			if(!bSuccess)
				error = GetLastError();
			else
			{
				jsonResponse.Format(jsonResponse+"%s",buffer);
				memset(buffer,0,10000);
			}
			
		}
		while(dwSize > 0);
		if(strlen(jsonResponse.GetBuffer()) > 0)
		{
			Document doc;
			doc.Parse(jsonResponse.GetBuffer());
			try
			{
				oauth_token_access = doc["access_token"].GetString();
				oauth_uid = doc["uid"].GetString();
				oauth_Header_api.Format(L"Authorization: Bearer %s",A2W(oauth_token_access));
			}
			catch(...)
			{
				bSuccess = false;
			}

		}
	}
	WinHttpCloseHandle(hSessionApi);
	WinHttpCloseHandle(hConnectApi);
	WinHttpCloseHandle(hRequestAuth);
	hSessionApi = NULL;
	hConnectApi = NULL;
	hRequestAuth = NULL;
	return bSuccess;

}
CList<file_folders,file_folders&>* DropBoxApi::ListFolderAndFiles(file_folders file_folder_info)
{
	USES_CONVERSION;
	int error;
	List_FoldersAndFiles.RemoveAll();
	if(file_folder_info.isFile && !file_folder_info.isFolder)
	{
		return NULL;
	}
	bool bSuccess;
	CStringA json = "{\"path\": \"\",\"recursive\": false,\"include_media_info\": true,\"include_deleted\": false}";
	CStringA jsonContinue = "{\"cursor\": \"\"}";
	CStringA jsonResponse;
	Document doc;
	StringBuffer jsonBuffer;
	Writer<StringBuffer> jsonWriter(jsonBuffer);
	doc.Parse(json.GetBuffer());
	doc["path"].SetString(file_folder_info.path.GetBuffer(),strlen(file_folder_info.path.GetBuffer()));
	if(strlen(oauth_token_access.GetBuffer()) != 0 && strlen(oauth_uid.GetBuffer()) != 0 && hSessionApi == NULL && hConnectApi == NULL)
	{
		hSessionApi = hSessionApi = WinHttpOpen( PROGRAM_NAME,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
		if(hSessionApi)
		{
			hConnectApi = WinHttpConnect( hSessionApi, API_URI,443, 0 );
		}
		if(hConnectApi)
		{
			hRequestApi = WinHttpOpenRequest( hConnectApi, L"POST",API_LIST_FOLDER,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
			error = GetLastError();
		}
	}
	else
		return NULL;
	if(hRequestApi)
	{
		doc.Accept(jsonWriter);
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,oauth_Header_api.GetBuffer(),wcslen(oauth_Header_api.GetBuffer()),WINHTTP_ADDREQ_FLAG_ADD );
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,CONTENT_HEADER,wcslen(CONTENT_HEADER),WINHTTP_ADDREQ_FLAG_ADD );
		error = GetLastError();
		CStringA val = jsonBuffer.GetString();
		bSuccess = WinHttpSendRequest( hRequestApi,WINHTTP_NO_ADDITIONAL_HEADERS,0,(void*)jsonBuffer.GetString(),strlen(jsonBuffer.GetString()),strlen(jsonBuffer.GetString()),0);
	}
	if(bSuccess)
		bSuccess = WinHttpReceiveResponse( hRequestApi, NULL);
	if(bSuccess)
	{
		jsonResponse = "";
		doc.SetObject();
		char buffer[10000];
		memset(buffer,0,10000);
		DWORD dwSize = 0;
		DWORD dwDownloaded= 0;
		bool moreData;
		do 
		{
			dwSize = 0;
			bSuccess = WinHttpQueryDataAvailable( hRequestApi, &dwSize );
			if (!dwSize)
			{
				doc.Parse(jsonResponse);
				if(!doc.HasMember("error_summary"))
				{
					try
					{
						bool moreData = doc["has_more"].GetBool();
						if(moreData)
						{
							CStringA cursor = doc["cursor"].GetString();
							bool successAdd = AddEntries(&doc);
							if(successAdd == false)
								return NULL;
							doc.SetObject();
							jsonResponse = "";
							doc.Parse(jsonContinue.GetBuffer());
							doc["cursor"].SetString(cursor.GetBuffer(),strlen(cursor.GetBuffer()));
							hRequestApi = WinHttpOpenRequest( hConnectApi, L"POST",API_LIST_FOLDER_CONTINUE,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
							if(hRequestApi)
							{	
								doc.Accept(jsonWriter);
								bSuccess = WinHttpSendRequest( hRequestApi,WINHTTP_NO_ADDITIONAL_HEADERS,0,(void*)jsonBuffer.GetString(),strlen(jsonBuffer.GetString()),strlen(jsonBuffer.GetString()),0);
							}
							if(bSuccess)
								bSuccess = WinHttpReceiveResponse( hRequestApi, NULL);
							if(bSuccess)
							{
								dwSize = 1;// to continue the loop
								continue;
							}
							return NULL; // if we couldnt get more data there was a problem return null
						}
						else
						{
							bool successAdd = AddEntries(&doc);
							if(successAdd == false)
								return NULL;
						}
					}
				catch(...)
				{
					return NULL;
				}
			}
			else
				return NULL;
			break;
			}
			if(!bSuccess){
				break;
			}
			bSuccess = WinHttpReadData( hRequestApi,buffer, dwSize, &dwDownloaded );
			if(!bSuccess)
				error = GetLastError();
			else
			{
				jsonResponse.Format(jsonResponse+"%s",buffer);
				memset(buffer,0,10000);
			}
			
		}
		while(dwSize > 0);


	}
	WinHttpCloseHandle(hSessionApi);
	WinHttpCloseHandle(hConnectApi);
	WinHttpCloseHandle(hRequestApi);
	hSessionApi = NULL;
	hConnectApi = NULL;
	hRequestApi = NULL;
	return &List_FoldersAndFiles;
}
bool DropBoxApi::UploadFile(char* pathDropBox,wchar_t* pathLocalHost)
{
	bool bSuccess;
	USES_CONVERSION;
	int error;
	unsigned __int64 offsetDropBoxApi;
	CStringA jsonApiArg = "{\"session_id\": \"\",\"offset\": 0}";
	CStringA jsonFinishArg = "{\"cursor\": {\"session_id\": \"\",\"offset\": 0},\"commit\": {\"path\": \"\",\"mode\": \"overwrite\",\"autorename\": true,\"mute\": false}}";
	CStringA jsonResponse;
	CStringA sessionId;
	CStringA dropBoxContentArgHeader;
	Document doc;
	DWORD dwSize;
	DWORD dwDownloaded= 0;
	const DWORD bufferAmount = 20000;
	char buffer[bufferAmount];
	memset(buffer,0,bufferAmount);
	///////////////////////////////////////////////////start get session_Id
	if(strlen(oauth_token_access.GetBuffer()) != 0 && strlen(oauth_uid.GetBuffer()) != 0 && hSessionApi == NULL && hConnectApi == NULL)
	{
		hSessionApi = hSessionApi = WinHttpOpen( PROGRAM_NAME,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
		if(hSessionApi)
		{
			hConnectApi = WinHttpConnect( hSessionApi, API_CONTENT_URI,443, 0 );
		}
		if(hConnectApi)
		{
			hRequestApi = WinHttpOpenRequest( hConnectApi, L"POST",API_UPLOAD_SESSION_START,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
			error = GetLastError();
		}
	}
	else
		return false;
	if(hRequestApi)
	{
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,oauth_Header_api.GetBuffer(),wcslen(oauth_Header_api.GetBuffer()),WINHTTP_ADDREQ_FLAG_ADD );
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,CONTENT_UPLOAD_HEADER,wcslen(CONTENT_UPLOAD_HEADER),WINHTTP_ADDREQ_FLAG_ADD );
		error = GetLastError();
		bSuccess = WinHttpSendRequest( hRequestApi,WINHTTP_NO_ADDITIONAL_HEADERS,0,0,0,0,0);
	}
	if(bSuccess)
		bSuccess = WinHttpReceiveResponse( hRequestApi, NULL);
	else
		return bSuccess;
	WinHttpQueryDataAvailable( hRequestApi, &dwSize );
	if(dwSize == 0)
		return false;
	WinHttpReadData( hRequestApi,buffer, dwSize, &dwDownloaded );
	if(dwDownloaded == 0)
		return false;
	doc.Parse(buffer);
	memset(buffer,0,bufferAmount);
	if(doc.HasMember("session_id"))
	{
		sessionId = doc["session_id"].GetString();
	}
	else
		return false;
	////////////////////////////////////////////////////////////////end get session_Id//startFileUpload
	WinHttpCloseHandle(hRequestApi);
	hRequestApi = NULL;
	offsetDropBoxApi = 0;
	std::ifstream inputFile;
	std::string fileChunkBuffer;
	inputFile.open(pathLocalHost,ios::in | ios::binary);
	inputFile.seekg (0, inputFile.end);
	__int64 fileLength = inputFile.tellg();
	if(fileLength == -1)
		return false;
	inputFile.seekg(0,inputFile.beg);
	__int64 pos = 0;
	__int64 numRead = 0;
	__int64 readAmount = 0;
	std::vector<BYTE> data;
	while(fileLength != numRead)
	{
		if((fileLength-pos) >= MAX_FILE_CHUNK_SIZE)
			readAmount = MAX_FILE_CHUNK_SIZE;
		else
			readAmount = fileLength-pos;
		data = std::vector<BYTE>(readAmount);
		inputFile.seekg(pos,inputFile.beg);
		inputFile.read((char *)&data[0],readAmount);
		fileChunkBuffer = std::string(data.begin(),data.end());
		numRead += readAmount;
		pos += readAmount;
		StringBuffer jsonBuffer;
		Writer<StringBuffer> jsonWriter(jsonBuffer);
		if(numRead ==  fileLength)
		{
			int val = fileChunkBuffer.length();
			//send and break close file
			doc.Parse(jsonFinishArg.GetBuffer());
			doc["cursor"].operator[]("session_id").SetString(sessionId.GetBuffer(),strlen(sessionId.GetBuffer()));
			doc["cursor"].operator[]("offset").SetInt64(offsetDropBoxApi);
			doc["commit"].operator[]("path").SetString(pathDropBox,strlen(pathDropBox));
			doc.Accept(jsonWriter);
			dropBoxContentArgHeader.Format("Dropbox-API-Arg: %s",jsonBuffer.GetString());
			UploadChunck(fileChunkBuffer,A2W(dropBoxContentArgHeader.GetBuffer()),true);
			inputFile.close();
		}
		else
		{
			doc.Parse(jsonApiArg.GetBuffer());
			doc["session_id"].SetString(sessionId.GetBuffer(),strlen(sessionId.GetBuffer()));
			doc["offset"].SetInt64(offsetDropBoxApi);
			doc.Accept(jsonWriter);
			dropBoxContentArgHeader.Format("Dropbox-API-Arg: %s",jsonBuffer.GetString());
			UploadChunck(fileChunkBuffer,A2W(dropBoxContentArgHeader.GetBuffer()),false);
		}
		offsetDropBoxApi += MAX_FILE_CHUNK_SIZE;//add offset after send always 6 million because more data 2 send

	}
	WinHttpCloseHandle(hSessionApi);
	WinHttpCloseHandle(hConnectApi);
	hSessionApi = NULL;
	hConnectApi = NULL;
	return bSuccess;
}
bool DropBoxApi::DownloadFile(char* pathDropBox,wchar_t* pathLocalHost)
{
	bool bSuccess;
	USES_CONVERSION;
	int error;
	unsigned __int64 offsetDropBoxApi;
	CStringA jsonApiArg = "{\"path\": \"\"}";
	CStringA dropBoxApiArg;
	CStringA jsonResponse;
	CStringA sessionId;
	CStringA dropBoxContentArgHeader;
	DWORD dwSize;
	DWORD dwDownloaded= 0;
	DWORD numBytesWritten;
	Document doc;
	StringBuffer jsonBuffer;
	Writer<StringBuffer> jsonWriter(jsonBuffer);
	std::vector<BYTE> data;
	//HANDLE hOutputFileAppend;
	//hOutputFileAppend = CreateFile(A2W(pathLocalHost),GENERIC_WRITE,0,NULL,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); // just to truncate file
	//CloseHandle(hOutputFileAppend);
	if(strlen(oauth_token_access.GetBuffer()) != 0 && strlen(oauth_uid.GetBuffer()) != 0 && hSessionApi == NULL && hConnectApi == NULL)
	{
		hSessionApi = hSessionApi = WinHttpOpen( PROGRAM_NAME,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
		if(hSessionApi)
		{
			hConnectApi = WinHttpConnect( hSessionApi, API_CONTENT_URI,443, 0 );
		}
		if(hConnectApi)
		{
			hRequestApi = WinHttpOpenRequest( hConnectApi, L"POST",API_DOWNLOAD_SESSION,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE );
			error = GetLastError();
		}
	}
	else
		return false;
	if(hRequestApi)
	{
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,oauth_Header_api.GetBuffer(),wcslen(oauth_Header_api.GetBuffer()),WINHTTP_ADDREQ_FLAG_ADD );
		doc.Parse(jsonApiArg);
		doc["path"].SetString(pathDropBox,strlen(pathDropBox));
		doc.Accept(jsonWriter);
		dropBoxApiArg.Format("Dropbox-API-Arg:%s",jsonBuffer.GetString());
		bSuccess = WinHttpAddRequestHeaders(hRequestApi,A2W(dropBoxApiArg.GetBuffer()),wcslen(A2W(dropBoxApiArg.GetBuffer())),WINHTTP_ADDREQ_FLAG_ADD );
		error = GetLastError();
		bSuccess = WinHttpSendRequest( hRequestApi,WINHTTP_NO_ADDITIONAL_HEADERS,0,0,0,0,0);
	}
	if(bSuccess)
		bSuccess = WinHttpReceiveResponse( hRequestApi, NULL);
	else
		return bSuccess;
	__int64 numRead = 0;
	fstream outPutFile;
	outPutFile.open(pathLocalHost,fstream::out | ios::binary | ios::trunc);
	__int64 pos = 0;
	do 
	{
		dwSize = 0;
		bSuccess = WinHttpQueryDataAvailable( hRequestApi, &dwSize );
		error = GetLastError();
		if (!dwSize)
			break;
		if(!bSuccess){
			break;
		}
		data = std::vector<BYTE>(dwSize);
		bSuccess = WinHttpReadData( hRequestApi,(LPVOID)&data[0], dwSize, &dwDownloaded);
		if(dwSize != dwDownloaded)
			data = std::vector<BYTE>(dwDownloaded);
		doc.Parse((char*)&data[0]);
		if(!doc.HasParseError() && numRead < 110)
		{
			try
			{
				if(doc.HasMember("error_summary"))
				{
					bSuccess = false;
					break;
				}
			}
			catch(...)
			{
				Sleep(1);
			}
		}
		outPutFile.seekg(pos,outPutFile.beg);
		outPutFile.write((char *)&data[0],dwDownloaded);
		if(!bSuccess)
			error = GetLastError();
		numRead += 	dwDownloaded;
		pos = numRead;
	}
	while(dwSize > 0);
	outPutFile.close();
	WinHttpCloseHandle(hSessionApi);
	WinHttpCloseHandle(hConnectApi);
	WinHttpCloseHandle(hRequestApi);
	hSessionApi = NULL;
	hConnectApi = NULL;
	hRequestApi = NULL;
	return bSuccess;
}
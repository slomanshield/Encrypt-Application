
// CloudSecureFileManager.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "DropBoxApi.h"
#include "EncryptFile.h"
#include "KeyDataBaseAccess.h"



// CCloudSecureFileManagerApp:
// See CloudSecureFileManager.cpp for the implementation of this class
//

class CCloudSecureFileManagerApp : public CWinApp
{
public:
	CCloudSecureFileManagerApp();
	static char * USER_PASSWORD;
	static char * dropBoxCode;
// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CCloudSecureFileManagerApp theApp;
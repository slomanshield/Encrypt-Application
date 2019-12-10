
// CloudSecureFileManagerDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CloudSecureFileManager.h"
#include "CloudSecureFileManagerDlg.h"
#include "afxdialogex.h"
#include "DeleteEntries.h"
#include "DatabasePasswordDlg.h"
#include "CreateKeyDatabaseDlg.h"
#include "dropBoxCode.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CCloudSecureFileManagerDlg dialog



BOOL CCloudSecureFileManagerDlg::PreTranslateMessage(MSG* pMsg)
{
	if( pMsg->message == WM_KEYDOWN )
    {
        if(pMsg->wParam == VK_RETURN )
        {
			USES_CONVERSION;
			CString userPathLocal;
			CString userPathDropbox;
			currentLocalPathEdit.GetWindowTextW(userPathLocal);
			currentDropboxPathEdit.GetWindowTextW(userPathDropbox);
			if(userPathDropbox.CompareNoCase(DROPBOX_ROOT_DIR_USER) == 0)
			{
				userPathDropbox = DROPBOX_ROOT_DIR;
			}

			if(userPathLocal.CompareNoCase(currentUserLocalPath) != 0)
			{
				currentUserLocalPath = userPathLocal;
				if(GetDirFiles(userPathLocal))
				{
					currentPathLocal = userPathLocal;
					parentPathLocal = currentPathLocal.Mid(0,currentPathLocal.ReverseFind(L'\\'));
				}

				PopulateLocalFileList();
			}
			if(userPathDropbox.CompareNoCase(currentUserDropboxPath) != 0)
			{
				currentUserDropboxPath = userPathDropbox;
				CStringA path = W2A(currentUserDropboxPath);
				if(GetDirFilesDropbox(path))
				{
					currentPathDropbox = userPathDropbox;
					parentPathDropbox = currentPathLocal.Mid(0,currentPathLocal.ReverseFind(L'/'));
				}

				PopulateDropboxFileList();
			}


            return TRUE;                // Do not process further
        }
    }
	

    return CWnd::PreTranslateMessage(pMsg);

}


CCloudSecureFileManagerDlg::CCloudSecureFileManagerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCloudSecureFileManagerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCloudSecureFileManagerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, listLocalMachine);
	DDX_Control(pDX, IDC_LIST3, listDropbox);
	DDX_Control(pDX, IDC_EDIT1, currentLocalPathEdit);
	DDX_Control(pDX, IDC_EDIT2, currentDropboxPathEdit);
	DDX_Control(pDX, IDC_LIST1, outputListCtrl);
}

BEGIN_MESSAGE_MAP(CCloudSecureFileManagerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_SIZE()
	ON_COMMAND(ID_KEYDATABASE_DELETEENTRIES, &CCloudSecureFileManagerDlg::OnKeydatabaseDeleteentries)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST2, &CCloudSecureFileManagerDlg::OnNMDbclickLocal)
	ON_BN_CLICKED(IDC_CONNECT_DROPBOX, &CCloudSecureFileManagerDlg::OnBnClickedConnectDropbox)
	ON_EN_KILLFOCUS(IDC_EDIT1, &CCloudSecureFileManagerDlg::OnEnKillfocusEdit1)
	ON_NOTIFY(LVN_KEYDOWN, IDC_LIST2, &CCloudSecureFileManagerDlg::RefreshLocalList)
	ON_COMMAND(ID_KEYDATABASE_LOGIN, &CCloudSecureFileManagerDlg::OnKeydatabaseLogin)
	ON_COMMAND(ID_KEYDATABASE_CREATENEW, &CCloudSecureFileManagerDlg::OnKeydatabaseCreatenew)
	ON_NOTIFY(NM_RCLICK, IDC_LIST2, &CCloudSecureFileManagerDlg::OnNMRClickList2)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST3, &CCloudSecureFileManagerDlg::OnNMDblclkDropbox)
	ON_NOTIFY(NM_RCLICK, IDC_LIST3, &CCloudSecureFileManagerDlg::OnNMRClickListDropBox)
	ON_NOTIFY(LVN_KEYDOWN, IDC_LIST3, &CCloudSecureFileManagerDlg::RefreshdropBoxList)
END_MESSAGE_MAP()


// CCloudSecureFileManagerDlg message handlers

bool CCloudSecureFileManagerDlg::GetRootDirFiles()
{
	WCHAR path[MAX_PATH];
	HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path);
	if(SUCCEEDED( result))
	{
		currentPathLocal = path;
		return true;
	}
	else
		return false;
}

bool CCloudSecureFileManagerDlg::GetRootDirFilesDropbox()
{
	file_folders testFileFolder;
	testFileFolder.isFile = false;
	testFileFolder.isFolder = true;
	testFileFolder.path = "";//make it empty to query root

	directoryDropboxItems = dropboxApi.ListFolderAndFiles(testFileFolder);
	if(directoryDropboxItems != NULL)
		return true;
}

bool CCloudSecureFileManagerDlg::GetDirFiles(CString path)
{
	userLocal tempEntry;
	localDirList.RemoveAll();
	WIN32_FIND_DATA ffd;
	CString internalPath = path;
	internalPath += L"\\*";
	HANDLE hFind = FindFirstFile(internalPath,&ffd);
	if(INVALID_HANDLE_VALUE  == hFind)
		return false;
	bool isParentDir;
	int listControlIndex = 0;
	LARGE_INTEGER fileSize;
	do
	{
	  memset(&tempEntry,0,sizeof(userLocal));
	  CString fileName = ffd.cFileName;
	  if(fileName.CompareNoCase(L"..") == 0 || fileName.CompareNoCase(L".") == 0)
		continue;




	  if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	  {
		  memcpy(&tempEntry.type,FILE_DIR,sizeof(FILE_DIR));
		  tempEntry.is_folder = true;
	  }
	  else
	  {
		  memcpy(&tempEntry.type,FILE_FILE,sizeof(FILE_FILE));
		  tempEntry.fileSize.LowPart = ffd.nFileSizeLow;
		  tempEntry.fileSize.HighPart = ffd.nFileSizeHigh;
		  tempEntry.is_folder = false;
		  tempEntry.fileTimeAccessed = ffd.ftLastAccessTime;
		 
		 
	  }
	   memcpy(&tempEntry.FileName[0],ffd.cFileName,sizeof(ffd.cFileName));

	   
	   

	   localDirList.AddTail(tempEntry);
	}while(FindNextFile(hFind, &ffd));

	return true;
}

bool CCloudSecureFileManagerDlg::GetDirFilesDropbox(CStringA path)
{
	file_folders temp;
	temp.path = path;
	directoryDropboxItems  = dropboxApi.ListFolderAndFiles(temp);
	if(directoryDropboxItems != NULL)
		return true;
	else
		return false;
}
void CCloudSecureFileManagerDlg::PopulateLocalFileList()
{
	listLocalMachine.DeleteAllItems();
	POSITION pos = localDirList.GetHeadPosition();
	userLocal tempEntry;
	SYSTEMTIME time;
	for(long long i = 0; i < localDirList.GetSize()+1;i++)
	{
		if(i != 0)
		{
			memset(&tempEntry,0,sizeof(userLocal));
			tempEntry = localDirList.GetNext(pos);
			CString fileSizeStr = L"";
			fileSizeStr.Format(L"%d",tempEntry.fileSize.QuadPart);
			CString type = L"";
			listLocalMachine.InsertItem(i,tempEntry.FileName);
			if(tempEntry.is_folder)
			{
				type = FILE_DIR;
			}
			else
			{
				type = FILE_FILE;
				CString timeStr;
				FileTimeToSystemTime(&tempEntry.fileTimeAccessed,&time);
				timeStr.Format(L"%d-%d-%d %d:%d:%d ",time.wYear,time.wMonth,time.wDay,time.wHour,time.wMinute,time.wSecond);
				listLocalMachine.SetItemText(i,3,timeStr);
			}

			
			listLocalMachine.SetItemText(i,1,fileSizeStr);
			listLocalMachine.SetItemText(i,2,type);

			

			
		}
		else
		{
			listLocalMachine.InsertItem(i,PARENT_DIR);
		}
	}
}

void CCloudSecureFileManagerDlg::PopulateDropboxFileList()
{
	USES_CONVERSION;
	listDropbox.DeleteAllItems();
	file_folders fileAttributesTemp;
	if(directoryDropboxItems == NULL)
		return;
	POSITION pos = directoryDropboxItems->GetHeadPosition();
	CStringW tempVal;
	CString type;

	for(long long i = 0; i < directoryDropboxItems->GetSize()+1;i++)
	{
		if(i != 0)
		{
			fileAttributesTemp = directoryDropboxItems->GetNext(pos);

			tempVal = A2W(fileAttributesTemp.name);
			listDropbox.InsertItem(i,tempVal);
			
			if(fileAttributesTemp.isFile)
				type = FILE_FILE;
			else if(fileAttributesTemp.isFolder)
				type = FILE_DIR;
			else
				type = FILE_FILE;

			listDropbox.SetItemText(i,1,type);

		}
		else
		{
			listDropbox.InsertItem(i,PARENT_DIR);
		}
	}

}

int CCloudSecureFileManagerDlg::CreateLocalMenuItemSelect(LPNMITEMACTIVATE pNMItemActivate)
{
	HMENU m_hMenu = CreatePopupMenu();
	POINT pontCur;
	GetCursorPos(&pontCur);
	int returnValue = 0;
	CString type = listLocalMachine.GetItemText(pNMItemActivate->iItem,2);
	CString fileName = listLocalMachine.GetItemText(pNMItemActivate->iItem,0);
	if(type.CompareNoCase(FILE_FILE) == 0)
	{
		InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, DELETE_FILE_MENU_SELECT, L"Delete");
		if(CCloudSecureFileManagerApp::USER_PASSWORD != NULL)
		{
			if(fileName.Find(L".encr") == -1)//if i has the correct extension we either Decrypt or enerypt
				InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, ENCRYPT_MENU_SELECT, L"Encrypt");
			else
				InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, DECRYPT_MENU_SELECT, L"Decrypt");
		}
		if(connected == true)
			InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, UPLOAD_MENU_SELECT, L"Upload");
		if(connected == true && CCloudSecureFileManagerApp::USER_PASSWORD != NULL)
			InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, ENCRYPT_UPLOAD_MENU_SELECT, L"Encrypt and Upload");
	}
	returnValue = TrackPopupMenu(m_hMenu, TPM_RETURNCMD , pontCur.x, pontCur.y, 0, m_hWnd, NULL); 
        
	return returnValue;
}

int CCloudSecureFileManagerDlg::CreateDropboxMenutItemselect(LPNMITEMACTIVATE pNMItemActivate)
{
	HMENU m_hMenu = CreatePopupMenu();
	POINT pontCur;
	GetCursorPos(&pontCur);
	int returnValue = 0;
	
	CString type = listDropbox.GetItemText(pNMItemActivate->iItem,1);
	CString fileName = listDropbox.GetItemText(pNMItemActivate->iItem,0);
	if(type.CompareNoCase(FILE_FILE) == 0)
	{
		if(connected == true)
			InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, DOWNLOAD_MENU_SELECT, L"Download");
		if(connected == true && CCloudSecureFileManagerApp::USER_PASSWORD != NULL && fileName.Find(L".encr") != -1)
			InsertMenu(m_hMenu, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, DOWNLOAD_DECRYPT_MENU_SELECT, L"Download and Decrypt");
	}
	
	returnValue = TrackPopupMenu(m_hMenu, TPM_RETURNCMD , pontCur.x, pontCur.y, 0, m_hWnd, NULL); 
        
	return returnValue;



}

BOOL CCloudSecureFileManagerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	/*initalize lists */

	/* check if it exists if it does not create new, if user clicks cancel it is ok they will just be unable to encrypt or decrypt*/
	
	bool exists = databaseAccess.CheckKeyFileExists();
	if(exists == false)
	{
		CreateKeyDatabaseDlg createDatabase;
		createDatabase.DoModal();
	}
	else
	{
		DatabasePasswordDlg enterPasswordDlg;
		enterPasswordDlg.DoModal();
	}

	listLocalMachine.InsertColumn(0,L"Name",LVCFMT_LEFT,200);
	listLocalMachine.InsertColumn(1,L"Size",LVCFMT_LEFT,100);
	listLocalMachine.InsertColumn(2,L"Type",LVCFMT_LEFT,50);
	listLocalMachine.InsertColumn(3,L"Date Modified",LVCFMT_LEFT,200);

	listDropbox.InsertColumn(0,L"Name",LVCFMT_LEFT,200);
	listDropbox.InsertColumn(1,L"Type",LVCFMT_LEFT,50);

	outputListCtrl.InsertColumn(0,L"File",LVCFMT_LEFT,200);
	outputListCtrl.InsertColumn(1,L"Action",LVCFMT_LEFT,100);

	currentUserDropboxPath = L"";
	currentUserLocalPath = L"";

	

	bool result = GetRootDirFiles();
	GetDirFiles(currentPathLocal);
	parentPathLocal = currentPathLocal.Mid(0,currentPathLocal.ReverseFind(L'\\'));

	PopulateLocalFileList();
	currentLocalPathEdit.SetWindowTextW(currentPathLocal);
	connected = false;//user will have to connected each session
	if(!result)
	{
		MessageBox(L"Could not get user path",L"Error",MB_OK | MB_ICONERROR);
		return true;
	}

	

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CCloudSecureFileManagerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CCloudSecureFileManagerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CCloudSecureFileManagerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CCloudSecureFileManagerDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	if(listLocalMachine != NULL_HANDLE)
	{
		CRect rect;
		CRect mainWindowRect;
		CRect desktopRect;

		listLocalMachine.GetWindowRect(&rect);
		MapWindowPoints(NULL,&mainWindowRect);

		int x = rect.left - mainWindowRect.left;
		int y = rect.top - mainWindowRect.top;
		
		::GetWindowRect(::GetActiveWindow(),desktopRect);
		listLocalMachine.SetWindowPos(NULL,x,y,rect.Width(),rect.Height(),SWP_SHOWWINDOW   );

		
		
	}

	if(listDropbox != NULL_HANDLE)
	{
		//listDropbox.MoveWindow(cx/5,cy/5,cx/2,cy/2);
	}

	if(outputListCtrl != NULL_HANDLE)
	{
		//outputListCtrl.MoveWindow(cx/2,cy/2,cx/2,cy/2);
	}

}

void CCloudSecureFileManagerDlg::OnKeydatabaseDeleteentries()
{
	DeleteEntries deleteEntries;
	deleteEntries.DoModal();
}

void CCloudSecureFileManagerDlg::OnKeydatabaseLogin()
{
	DatabasePasswordDlg databaseLoginDlg;
	databaseLoginDlg.DoModal();
}

void CCloudSecureFileManagerDlg::OnKeydatabaseCreatenew()
{
	CreateKeyDatabaseDlg createDatabaseDlg;
	createDatabaseDlg.DoModal();
}

void CCloudSecureFileManagerDlg::OnNMDbclickLocal(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	CString fileName = listLocalMachine.GetItemText(pNMItemActivate->iItem,0);
	CString type = listLocalMachine.GetItemText(pNMItemActivate->iItem,2);
	CString pathUsed = currentPathLocal;


	if(fileName.CompareNoCase(PARENT_DIR) == 0)
	{
		if(GetDirFiles(parentPathLocal));
		{
			currentPathLocal = parentPathLocal;
			parentPathLocal = currentPathLocal.Mid(0,currentPathLocal.ReverseFind(L'\\'));
		}
		PopulateLocalFileList();

	}
	else if (type.CompareNoCase(FILE_DIR) == 0)
	{
		pathUsed += L"\\";
		pathUsed += fileName;
		if(GetDirFiles(pathUsed))
		{
			currentPathLocal = pathUsed;
			parentPathLocal = currentPathLocal.Mid(0,currentPathLocal.ReverseFind(L'\\'));
		}
		PopulateLocalFileList();

	}
	else if(type.CompareNoCase(FILE_FILE) == 0)
	{
		pathUsed += L"\\";
		pathUsed += fileName;
		ShellExecute(0, 0, pathUsed, 0, 0 , SW_SHOW );
	}
	currentLocalPathEdit.SetWindowTextW(currentPathLocal);
	
	*pResult = 0;
}

void CCloudSecureFileManagerDlg::OnNMDblclkDropbox(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	USES_CONVERSION;
	CString fileName = listDropbox.GetItemText(pNMItemActivate->iItem,0);
	CString type = listDropbox.GetItemText(pNMItemActivate->iItem,1);
	CStringA pathUsed = W2A(currentPathDropbox);
	CStringA parentUsed = W2A(parentPathDropbox);

	if(fileName.CompareNoCase(PARENT_DIR) == 0)
	{
		if(GetDirFilesDropbox(parentUsed))
		{
			currentPathDropbox = parentUsed;
			parentPathDropbox = currentPathDropbox.Mid(0,currentPathDropbox.ReverseFind(L'/'));
		}

		PopulateDropboxFileList();

	}
	else if (type.CompareNoCase(FILE_DIR) == 0)
	{
		pathUsed += L"/";
		pathUsed += fileName;
		if(GetDirFilesDropbox(pathUsed))
		{
			currentPathDropbox = pathUsed;
			parentPathDropbox = currentPathDropbox.Mid(0,currentPathDropbox.ReverseFind(L'/'));
		}
		PopulateDropboxFileList();

	}
	currentDropboxPathEdit.SetWindowTextW(currentPathDropbox);


	*pResult = 0;
}



void CCloudSecureFileManagerDlg::OnBnClickedConnectDropbox()
{
	dropboxApi.LoadAuthorizePage();

	dropBoxCode dropboxCode;

	dropboxCode.DoModal();

	if(CCloudSecureFileManagerApp::dropBoxCode == NULL)
	{
		MessageBox(L"Error invalid code",L"Error",MB_OK | MB_ICONERROR);
		return;
	}

	bool authorized = dropboxApi.AuthorizeUser(CCloudSecureFileManagerApp::dropBoxCode);

	if(!authorized)
	{
		MessageBox(L"Error could not authorize",L"Error",MB_OK | MB_ICONERROR);
		delete [] CCloudSecureFileManagerApp::dropBoxCode;
		connected = false;
	}
	else
		connected = true;
	if(connected == true)
	{
		if(GetRootDirFilesDropbox())
		{
			PopulateDropboxFileList();
		}

		currentPathDropbox = DROPBOX_ROOT_DIR;
		parentPathDropbox = DROPBOX_ROOT_DIR;
		currentUserDropboxPath = DROPBOX_ROOT_DIR;
		currentDropboxPathEdit.SetWindowTextW(DROPBOX_ROOT_DIR_USER);
	}
}




/* not using */
void CCloudSecureFileManagerDlg::OnEnKillfocusEdit1()
{
}


void CCloudSecureFileManagerDlg::RefreshLocalList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVKEYDOWN pLVKeyDow = reinterpret_cast<LPNMLVKEYDOWN>(pNMHDR);
	WORD keyPressed = pLVKeyDow->wVKey;
	if(keyPressed == F5_UPDATE_KEY)
	{
		if(GetDirFiles(currentPathLocal))
			PopulateLocalFileList();
	}
	*pResult = 0;
}

void CCloudSecureFileManagerDlg::RefreshdropBoxList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVKEYDOWN pLVKeyDow = reinterpret_cast<LPNMLVKEYDOWN>(pNMHDR);
	WORD keyPressed = pLVKeyDow->wVKey;
	USES_CONVERSION;
	if(keyPressed == F5_UPDATE_KEY)
	{
		CStringA path = W2A(currentPathDropbox);
		if(GetDirFilesDropbox(path))
			PopulateDropboxFileList();
	}
	*pResult = 0;
}








void CCloudSecureFileManagerDlg::OnNMRClickList2(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

	int valueClicked = CreateLocalMenuItemSelect(pNMItemActivate);

	CString fullFilePath = currentPathLocal;
	CString fileName = listLocalMachine.GetItemText(pNMItemActivate->iItem,0);
	fullFilePath += L"\\";
	fullFilePath += fileName;
	CString newFileEncryptedPath = fullFilePath.Mid(0,fullFilePath.Find(L"."));
	newFileEncryptedPath.Append(L".encr");
	if(valueClicked == ENCRYPT_MENU_SELECT || valueClicked == ENCRYPT_UPLOAD_MENU_SELECT)
	{
		int valueCount = outputListCtrl.GetItemCount();
		outputListCtrl.InsertItem(valueCount,fileName);
		outputListCtrl.SetItemText(valueCount,1,ENCRYPT_ACTION);
		Sleep(10);
		Public_Private_Key keypairs = encryptHandler.GeneratePublicPrivateKey(RSA_KEY_SIZE);
		char* delimiter = encryptHandler.GenerateDelimiter();//must delete delimiter
		char tagExtension [TAG_LEN];
		char tagFile [TAG_LEN];

		bool success = encryptHandler.EncryptFile(fullFilePath.GetBuffer(),delimiter,keypairs,(unsigned char*)tagExtension,(unsigned char*)tagFile);
		if(!success)
			MessageBox(L"Could not encrypt file",L"Error",MB_OK | MB_ICONERROR);
		if(success)
		{
			success = databaseAccess.SetFileEntry(newFileEncryptedPath.GetBuffer(),keypairs.publicKey,keypairs.privateKey,delimiter,(unsigned char *)CCloudSecureFileManagerApp::USER_PASSWORD,tagExtension,tagFile);
		}
		if(!success)
			MessageBox(L"Could not make database entry",L"Error",MB_OK | MB_ICONERROR);
		delete [] delimiter;//always delete
		valueCount = outputListCtrl.GetItemCount();
		outputListCtrl.InsertItem(valueCount,fileName);
		outputListCtrl.SetItemText(valueCount,1,ENCRYPT_ACTION_DONE);
		encryptHandler.ClearKeyPairs(keypairs);
		//refresh directory
		if(GetDirFiles(currentPathLocal))
			PopulateLocalFileList();
		if( valueClicked == ENCRYPT_UPLOAD_MENU_SELECT && success)
		{
			valueCount = outputListCtrl.GetItemCount();
			outputListCtrl.InsertItem(valueCount,fileName);
			outputListCtrl.SetItemText(valueCount,1,UPLOAD_ACTION);
			USES_CONVERSION;
			CStringA pathUpload = "";
			if(currentPathDropbox.CompareNoCase(DROPBOX_ROOT_DIR) == 0)
				pathUpload += "/";
			else
			{
				pathUpload = currentPathDropbox;
				pathUpload += "/";
			}
			pathUpload += newFileEncryptedPath.Mid(newFileEncryptedPath.ReverseFind(L'\\')+1);
			bool success = dropboxApi.UploadFile(pathUpload.GetBuffer(),newFileEncryptedPath.GetBuffer());
			if(!success)
				MessageBox(L"Error uploading file",L"Error",MB_OK | MB_ICONERROR);
			else
			{
				valueCount = outputListCtrl.GetItemCount();
				outputListCtrl.InsertItem(valueCount,fileName);
				outputListCtrl.SetItemText(valueCount,1,UPLOAD_ACTION_DONE);
				if(GetDirFilesDropbox(W2A(currentPathDropbox)))//refresh list
					PopulateDropboxFileList();
			}
		}

	}
	else if(valueClicked == DECRYPT_MENU_SELECT)
	{
		int valueCount = outputListCtrl.GetItemCount();
		outputListCtrl.InsertItem(valueCount,fileName);
		outputListCtrl.SetItemText(valueCount,1,DECRYPTING_ACTION);

		Public_Private_Key keypairs;
		FileParameters* fileParams = databaseAccess.GetFileEntry(fullFilePath.GetBuffer(),(unsigned char *)CCloudSecureFileManagerApp::USER_PASSWORD); // must delete file params char pointers
		if(fileParams != NULL)
		{
			keypairs.publicKey = fileParams->publicKey;
			keypairs.privateKey = fileParams->privateKey;
			bool success = encryptHandler.DecryptFile(fullFilePath.GetBuffer(),fileParams->delimiter,keypairs,(unsigned char*)fileParams->tagExtension,(unsigned char*)fileParams->tagFile);
			if(!success)
				MessageBox(L"Could not Decrypt file!",L"Error",MB_OK | MB_ICONERROR);
			else
			{
				if(GetDirFiles(currentPathLocal))//if Decryption successful
					PopulateLocalFileList();
			}
			databaseAccess.ClearFileParams(fileParams);

			valueCount = outputListCtrl.GetItemCount();
			outputListCtrl.InsertItem(valueCount,fileName);
			outputListCtrl.SetItemText(valueCount,1,DECRYPT_ACTION_DONE);
		}
		else
			MessageBox(L"Could not find file entry in database!",L"Error",MB_OK | MB_ICONERROR);
	}
	else if(valueClicked == UPLOAD_MENU_SELECT)
	{
		int valueCount = outputListCtrl.GetItemCount();
		outputListCtrl.InsertItem(valueCount,fileName);
		outputListCtrl.SetItemText(valueCount,1,UPLOAD_ACTION);

		USES_CONVERSION;
		CStringA pathUpload = "";
		if(currentPathDropbox.CompareNoCase(DROPBOX_ROOT_DIR) == 0)
			pathUpload += "/";
		else
		{
			pathUpload = currentPathDropbox;
			pathUpload += "/";
		}
		pathUpload += fileName;
		bool success = dropboxApi.UploadFile(pathUpload.GetBuffer(),fullFilePath.GetBuffer());
		if(!success)
			MessageBox(L"Error uploading file",L"Error",MB_OK | MB_ICONERROR);
		else
		{
			valueCount = outputListCtrl.GetItemCount();
			outputListCtrl.InsertItem(valueCount,fileName);
			outputListCtrl.SetItemText(valueCount,1,UPLOAD_ACTION_DONE);
			if(GetDirFilesDropbox(W2A(currentPathDropbox)))//refresh list
				PopulateDropboxFileList();
		}
	}
	else if(valueClicked == DELETE_FILE_MENU_SELECT)
	{
		BOOL successDelete = DeleteFileW(fullFilePath);
		if(!successDelete)
			MessageBox(L"Error deleting file",L"Error",MB_OK | MB_ICONERROR);
		else
		{
			if(GetDirFiles(currentPathLocal))
				PopulateLocalFileList();
		}
	}
	else if(valueClicked == NONE_MENU_SELECT)
	{
		Sleep(1);//do nothing
	}
	else
		MessageBox(L"Somehow you clicked something that doesn't actually exist!",L"Error",MB_OK | MB_ICONERROR);



	
	*pResult = 0;
}






void CCloudSecureFileManagerDlg::OnNMRClickListDropBox(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	int valueClicked = CreateDropboxMenutItemselect(pNMItemActivate);

	CString fullFilePathLocal = currentPathLocal;
	fullFilePathLocal += L"\\";
	CString fileName = listDropbox.GetItemText(pNMItemActivate->iItem,0);
	fullFilePathLocal += fileName;

	CStringA fulledropBoxFilePath = "";
	if(currentPathDropbox.CompareNoCase(DROPBOX_ROOT_DIR) == 0)
		fulledropBoxFilePath += "/";
	else
	{
		fulledropBoxFilePath += currentPathDropbox;
		fulledropBoxFilePath += "/";
	}
	fulledropBoxFilePath += fileName;
	if(valueClicked == DOWNLOAD_MENU_SELECT || valueClicked == DOWNLOAD_DECRYPT_MENU_SELECT)
	{
		int valueCount = outputListCtrl.GetItemCount();
		outputListCtrl.InsertItem(valueCount,fileName);
		outputListCtrl.SetItemText(valueCount,1,DOWNLOAD_ACTION);

		bool success  = dropboxApi.DownloadFile(fulledropBoxFilePath.GetBuffer(),fullFilePathLocal.GetBuffer());
		if(!success)
			MessageBox(L"Error downloading file",L"Error",MB_OK | MB_ICONERROR);
		else
		{
			valueCount = outputListCtrl.GetItemCount();
			outputListCtrl.InsertItem(valueCount,fileName);
			outputListCtrl.SetItemText(valueCount,1,DOWNLOAD_ACTION_DONE);
		}
		if(success && valueClicked == DOWNLOAD_DECRYPT_MENU_SELECT)
		{
			valueCount = outputListCtrl.GetItemCount();
			outputListCtrl.InsertItem(valueCount,fileName);
			outputListCtrl.SetItemText(valueCount,1,DECRYPTING_ACTION);

			Public_Private_Key keypairs;
			FileParameters* fileParams = databaseAccess.GetFileEntry(fullFilePathLocal.GetBuffer(),(unsigned char *)CCloudSecureFileManagerApp::USER_PASSWORD); // must delete file params char pointers
			if(fileParams != NULL)
			{
				keypairs.publicKey = fileParams->publicKey;
				keypairs.privateKey = fileParams->privateKey;
				bool success = encryptHandler.DecryptFile(fullFilePathLocal.GetBuffer(),fileParams->delimiter,keypairs,(unsigned char*)fileParams->tagExtension,(unsigned char*)fileParams->tagFile);
				if(!success)
					MessageBox(L"Could not Decrypt file!",L"Error",MB_OK | MB_ICONERROR);
				else
				{
					if(GetDirFiles(currentPathLocal))//if Decryption successful
						PopulateLocalFileList();
				}
				databaseAccess.ClearFileParams(fileParams);

				valueCount = outputListCtrl.GetItemCount();
				outputListCtrl.InsertItem(valueCount,fileName);
				outputListCtrl.SetItemText(valueCount,1,DECRYPT_ACTION_DONE);

			}
			else
				MessageBox(L"Could not find file entry in database!",L"Error",MB_OK | MB_ICONERROR);
		}
	}


	*pResult = 0;
}



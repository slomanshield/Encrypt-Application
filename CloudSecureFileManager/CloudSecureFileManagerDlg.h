
// CloudSecureFileManagerDlg.h : header file
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
struct userLocal
{
	WCHAR type[MAX_PATH+1000]; 
	WCHAR FileName[MAX_PATH+1000]; 
	LARGE_INTEGER fileSize;
	FILETIME fileTimeAccessed;
	bool is_folder;
};

#define NULL_HANDLE ((HANDLE)(LONG_PTR)0)

#define UPLOAD_ACTION L"Uploading"
#define UPLOAD_ACTION_DONE L"Uploaded"
#define DOWNLOAD_ACTION_DONE L"Downloaded"
#define DOWNLOAD_ACTION L"Downloading"
#define ENCRYPT_ACTION_DONE L"Encrypted"
#define ENCRYPT_ACTION L"Encrypting"
#define DECRYPT_ACTION_DONE L"Decrypted"
#define DECRYPTING_ACTION L"Decrypting"

#define DROPBOX_ROOT_DIR_USER L"/"
#define DROPBOX_ROOT_DIR L""

#define FILE_DIR L"DIR"
#define FILE_FILE L"FILE"
#define PARENT_DIR L"..."
#define UPDATE_LOCAL_USER_INPUT
#define UPDATE_DROPBOX_USER_INPUT
#define F5_UPDATE_KEY 116

#define NONE_MENU_SELECT 0
#define ENCRYPT_MENU_SELECT 1
#define DECRYPT_MENU_SELECT 2
#define ENCRYPT_UPLOAD_MENU_SELECT 3
#define UPLOAD_MENU_SELECT 4
#define DOWNLOAD_MENU_SELECT 5
#define DOWNLOAD_DECRYPT_MENU_SELECT 6
#define DELETE_FILE_MENU_SELECT 7
// CCloudSecureFileManagerDlg dialog
class CCloudSecureFileManagerDlg : public CDialogEx
{
// Construction
public:
	CCloudSecureFileManagerDlg(CWnd* pParent = NULL);	// standard constructor
	BOOL PreTranslateMessage(MSG* pMsg);
	void OnSize(UINT nType, int cx, int cy);
// Dialog Data
	enum { IDD = IDD_CLOUDSECUREFILEMANAGER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnKeydatabaseDeleteentries();
private:
	BOOL connectedToDropBox;
	CString currentPathLocal;
	CString parentPathLocal;
	CString currentPathDropbox;
	CString parentPathDropbox;
	CString currentUserLocalPath;
	CString currentUserDropboxPath;
	KeyDataBaseAccess databaseAccess;
	DropBoxApi dropboxApi;
	FileEncrypt encryptHandler;


	CListCtrl listLocalMachine;
	CListCtrl listDropbox;
	CListCtrl outputListCtrl;
	CList<userLocal,userLocal> localDirList;
	CList<file_folders,file_folders&>* directoryDropboxItems;
	CEdit currentDropboxPathEdit;
	CEdit currentLocalPathEdit;

	bool GetRootDirFiles();
	bool GetRootDirFilesDropbox();

	bool GetDirFiles(CString path);
	bool GetDirFilesDropbox(CStringA path);
	//bool GetDirFilesDropbox(file_folders path);
	bool connected;
	
	void PopulateLocalFileList();
	void PopulateDropboxFileList();
	
	int CreateLocalMenuItemSelect(LPNMITEMACTIVATE pNMItemActivate);
	int CreateDropboxMenutItemselect(LPNMITEMACTIVATE pNMItemActivate);
	
	
public:
	afx_msg void OnNMDbclickLocal(NMHDR *pNMHDR, LRESULT *pResult);

	afx_msg void OnBnClickedConnectDropbox();
	afx_msg void updateLocalPathUser();
	afx_msg void OnEnKillfocusEdit1();
	afx_msg void RefreshLocalList(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnKeydatabaseLogin();
	afx_msg void OnKeydatabaseCreatenew();
	afx_msg void OnNMRClickList2(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemchangedList3(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMDblclkDropbox(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMRClickListDropBox(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void RefreshdropBoxList(NMHDR *pNMHDR, LRESULT *pResult);
};

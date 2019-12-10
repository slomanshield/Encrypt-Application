// DatabasePasswordDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CloudSecureFileManager.h"
#include "DatabasePasswordDlg.h"
#include "afxdialogex.h"


// DatabasePasswordDlg dialog

IMPLEMENT_DYNAMIC(DatabasePasswordDlg, CDialog)

DatabasePasswordDlg::DatabasePasswordDlg(CWnd* pParent /*=NULL*/)
	: CDialog(DatabasePasswordDlg::IDD, pParent)
{

}

DatabasePasswordDlg::~DatabasePasswordDlg()
{
}

void DatabasePasswordDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT2, passwordEdit);
}


BEGIN_MESSAGE_MAP(DatabasePasswordDlg, CDialog)
	ON_BN_CLICKED(IDC_PASSWORD_SUBMIT, &DatabasePasswordDlg::OnBnClickedPasswordSubmit)
END_MESSAGE_MAP()


// DatabasePasswordDlg message handlers

void DatabasePasswordDlg::LoginUser()
{
	USES_CONVERSION;
	/*test the password if fails keep it at null*/
	CString password;
	passwordEdit.GetWindowTextW(password);
	CStringA passwordA = W2A(password);
	bool success = false;

	KeyDataBaseAccess databaseAccess;
	success = databaseAccess.CheckPasswd((unsigned char*)passwordA.GetBuffer());
	
	if(success)
	{
		if(CCloudSecureFileManagerApp::USER_PASSWORD != NULL)
			delete [] CCloudSecureFileManagerApp::USER_PASSWORD;
		char* passwordBuffer = new char[passwordA.GetLength()+1];
		ZeroMemory(passwordBuffer,passwordA.GetLength()+1);
		memcpy(passwordBuffer,passwordA.GetBuffer(),passwordA.GetLength()+1);
		CCloudSecureFileManagerApp::USER_PASSWORD = passwordBuffer;
	}
	else
		MessageBox(L"Incorrect password for user database",L"Error",MB_OK | MB_ICONERROR);


	this->OnCancel();

}

BOOL DatabasePasswordDlg::PreTranslateMessage(MSG* pMsg)
{
	if( pMsg->message == WM_KEYDOWN )
    {
        if(pMsg->wParam == VK_RETURN )
        {
			LoginUser();
			return true;
		}

	}

	return CWnd::PreTranslateMessage(pMsg);

}

void DatabasePasswordDlg::OnBnClickedPasswordSubmit()
{
	LoginUser();
}

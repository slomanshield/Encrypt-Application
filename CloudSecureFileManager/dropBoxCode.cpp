// dropBoxCode.cpp : implementation file
//

#include "stdafx.h"
#include "CloudSecureFileManager.h"
#include "dropBoxCode.h"
#include "afxdialogex.h"


// dropBoxCode dialog

IMPLEMENT_DYNAMIC(dropBoxCode, CDialog)

dropBoxCode::dropBoxCode(CWnd* pParent /*=NULL*/)
	: CDialog(dropBoxCode::IDD, pParent)
{

}

dropBoxCode::~dropBoxCode()
{
}

void dropBoxCode::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, codeEditCtrl);
}

BOOL dropBoxCode::PreTranslateMessage(MSG* pMsg)
{
	if( pMsg->message == WM_KEYDOWN )
    {
        if(pMsg->wParam == VK_RETURN )
        {
			OnBnClickedButton1();
		}

	}

	return CWnd::PreTranslateMessage(pMsg);

}


BEGIN_MESSAGE_MAP(dropBoxCode, CDialog)
	ON_BN_CLICKED(IDC_BUTTON1, &dropBoxCode::OnBnClickedButton1)
END_MESSAGE_MAP()


// dropBoxCode message handlers


void dropBoxCode::OnBnClickedButton1()
{
	USES_CONVERSION;
	CString code;
	CStringA codeAnsi;
	codeEditCtrl.GetWindowTextW(code);
	if(code.GetLength() != 0)
	{
		codeAnsi = W2A(code);
		if(CCloudSecureFileManagerApp::dropBoxCode != NULL)
			delete [] CCloudSecureFileManagerApp::dropBoxCode;

		CCloudSecureFileManagerApp::dropBoxCode = new char[codeAnsi.GetLength()+1];
		ZeroMemory(CCloudSecureFileManagerApp::dropBoxCode,codeAnsi.GetLength()+1);

		memcpy(CCloudSecureFileManagerApp::dropBoxCode,codeAnsi.GetBuffer(),codeAnsi.GetLength()+1);

		this->OnCancel();
		
	}
	else
		MessageBox(L"Can not have an empty code",L"Error",MB_OK | MB_ICONERROR);
}

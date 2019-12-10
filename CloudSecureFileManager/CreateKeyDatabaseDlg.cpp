// CreateKeyDatabaseDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CloudSecureFileManager.h"
#include "CreateKeyDatabaseDlg.h"
#include "afxdialogex.h"


// CreateKeyDatabaseDlg dialog

IMPLEMENT_DYNAMIC(CreateKeyDatabaseDlg, CDialog)

CreateKeyDatabaseDlg::CreateKeyDatabaseDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CreateKeyDatabaseDlg::IDD, pParent)
{

}

CreateKeyDatabaseDlg::~CreateKeyDatabaseDlg()
{
}

BOOL CreateKeyDatabaseDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	passwordChkBox.SetCheck(1);//default to just password

	return true;
}

void CreateKeyDatabaseDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, password);
	DDX_Control(pDX, IDC_CHECK1, passwordChkBox);
	DDX_Control(pDX, IDC_CHECK2, password_hardwareChkBox);
}


BEGIN_MESSAGE_MAP(CreateKeyDatabaseDlg, CDialog)
	ON_BN_CLICKED(IDC_CHECK1, &CreateKeyDatabaseDlg::OnBnClickedPassword)
	ON_BN_CLICKED(IDC_CHECK2, &CreateKeyDatabaseDlg::OnBnClickedPasswordHardware)
	ON_BN_CLICKED(IDC_CREATE_DATABASE, &CreateKeyDatabaseDlg::OnBnClickedCreateDatabase)
END_MESSAGE_MAP()


// CreateKeyDatabaseDlg message handlers


void CreateKeyDatabaseDlg::OnBnClickedPassword()
{
	if(password_hardwareChkBox.GetCheck() == BST_CHECKED)
		password_hardwareChkBox.SetCheck(BST_UNCHECKED);
}


void CreateKeyDatabaseDlg::OnBnClickedPasswordHardware()
{
	if(passwordChkBox.GetCheck() == BST_CHECKED)
		passwordChkBox.SetCheck(BST_UNCHECKED);
}





void CreateKeyDatabaseDlg::OnBnClickedCreateDatabase()
{
	/* check if the database exits, if it does warn the user and allow for overwrite (do this in a message box) also check if password is empty  */
	USES_CONVERSION;
	CString passwordStr;
	password.GetWindowTextW(passwordStr);
	int passwordOnly = passwordChkBox.GetCheck();
	int password_hardware =  password_hardwareChkBox.GetCheck();

	if(passwordStr.GetLength() == 0)
	{
		MessageBox(L"You must have at least 1 character as a password,\nbut try to make it a bit longer than 1 character ;)",L"Error",MB_OK | MB_ICONERROR);
		return;
	}

	CStringA passwordStrA = W2A(passwordStr);

	KeyDataBaseAccess databaseAccess;

	bool exists = databaseAccess.CheckKeyFileExists();

	if(exists)
	{
		int userDecision =  MessageBox(L"A KeyDatabase already exists would you like to overwrite and clear the data?\nIf you choose to do so you will no be able to decrypt files that were previously encrypted",L"Warning",MB_YESNO | MB_ICONWARNING);
		if(userDecision == IDYES )
		{
			bool passwordCreateVal = databaseAccess.CreateNewKeyDataBaseFile((bool)passwordOnly,(bool)password_hardware,(unsigned char*)passwordStrA.GetBuffer());
			if(!passwordCreateVal)
				MessageBox(L"Could not create new Database",L"Error",MB_OK | MB_ICONERROR);
			else
			{
				if(CCloudSecureFileManagerApp::USER_PASSWORD != NULL)
					delete [] CCloudSecureFileManagerApp::USER_PASSWORD;
				char* passwordBuffer = new char[passwordStrA.GetLength()+1];
				ZeroMemory(passwordBuffer,passwordStrA.GetLength()+1);
				memcpy(passwordBuffer,passwordStrA.GetBuffer(),passwordStrA.GetLength()+1);
				CCloudSecureFileManagerApp::USER_PASSWORD = passwordBuffer;

			}
		}
	}
	else
	{
		bool passwordCreateVal = databaseAccess.CreateNewKeyDataBaseFile((bool)passwordOnly,(bool)password_hardware,(unsigned char*)passwordStrA.GetBuffer());
		if(!passwordCreateVal)
			MessageBox(L"Could not create new Database",L"Error",MB_OK | MB_ICONERROR);
		else
		{
			if(CCloudSecureFileManagerApp::USER_PASSWORD != NULL)
				delete [] CCloudSecureFileManagerApp::USER_PASSWORD;
			char* passwordBuffer = new char[passwordStrA.GetLength()+1];
			ZeroMemory(passwordBuffer,passwordStrA.GetLength()+1);
			memcpy(passwordBuffer,passwordStrA.GetBuffer(),passwordStrA.GetLength()+1);
			CCloudSecureFileManagerApp::USER_PASSWORD = passwordBuffer;
		}
	}

	this->OnCancel();
}

// DeleteEntries.cpp : implementation file
//

#include "stdafx.h"
#include "CloudSecureFileManager.h"
#include "DeleteEntries.h"
#include "afxdialogex.h"



// DeleteEntries dialog

IMPLEMENT_DYNAMIC(DeleteEntries, CDialog)

DeleteEntries::DeleteEntries(CWnd* pParent /*=NULL*/)
	: CDialog(DeleteEntries::IDD, pParent)
{

}

DeleteEntries::~DeleteEntries()
{
	databaseAccess.ClearKeyDataBaseList();
}

BOOL DeleteEntries::OnInitDialog()
{
	CDialog::OnInitDialog();

	FileList.InsertColumn(0,L"File Name",LVCFMT_LEFT,300);

	FileList.SetExtendedStyle(LVS_EX_CHECKBOXES);
	if(CCloudSecureFileManagerApp::USER_PASSWORD != NULL)
	{
		databaseAccess.ClearKeyDataBaseList();
		fileEntryList = databaseAccess.GetKeyDataBaseList((unsigned char*)CCloudSecureFileManagerApp::USER_PASSWORD);
		if(fileEntryList != NULL)
		{
			if(fileEntryList->GetSize() > 0)
			{
				POSITION pos = fileEntryList->GetHeadPosition();
				FileList.DeleteAllItems();
				for(long long i = 0 ; i < fileEntryList->GetSize();i++)
				{
					FileParameters* fileParams = fileEntryList->GetNext(pos);
					FileList.InsertItem(i,fileParams->fileName);
				}
			}
		}
	}
	return true;
}

void DeleteEntries::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, FileList);
}


BEGIN_MESSAGE_MAP(DeleteEntries, CDialog)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &DeleteEntries::OnLvnItemchangedList1)
	ON_BN_CLICKED(IDC_BUTTON_DELETE, &DeleteEntries::OnBnClickedButtonDelete)
END_MESSAGE_MAP()


// DeleteEntries message handlers


void DeleteEntries::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void DeleteEntries::OnBnClickedButtonDelete()
{
	/* Get List and check with the check box and flag the files for deletion then call delete */
	bool checked = false;
	POSITION pos;
	FileParameters* fileParams;
	if(fileEntryList != NULL)
	{
		if(fileEntryList->GetSize() > 0)
		{
			pos = fileEntryList->GetHeadPosition();
			for(long long i = 0; i < FileList.GetItemCount();i++)//they are put in the same order as it is gotten from the database
			{
				checked = FileList.GetCheck(i);
				FileParameters* fileParams = fileEntryList->GetNext(pos);
				if(checked)
					fileParams->keep = false;
			}

			bool success = databaseAccess.DeleteFileEntrys((unsigned char*)CCloudSecureFileManagerApp::USER_PASSWORD);
			if(!success)
				MessageBox(L"Could not delete !",L"Error",MB_OK | MB_ICONERROR);
		}
	}
	else
		MessageBox(L"Nothing to delete!",L"Error",MB_OK | MB_ICONERROR);

	this->OnCancel();//close dialog
}

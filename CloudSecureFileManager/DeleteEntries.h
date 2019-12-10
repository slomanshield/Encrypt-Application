#pragma once
#include "afxcmn.h"


// DeleteEntries dialog

class DeleteEntries : public CDialog
{
	DECLARE_DYNAMIC(DeleteEntries)

public:
	DeleteEntries(CWnd* pParent = NULL);   // standard constructor
	virtual ~DeleteEntries();

// Dialog Data
	enum { IDD = ID_DELETE_ENTRIES };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
private:
	CListCtrl FileList;
	CList<FileParameters*>* fileEntryList;
	KeyDataBaseAccess databaseAccess;
public:
	afx_msg void OnBnClickedButtonDelete();
};



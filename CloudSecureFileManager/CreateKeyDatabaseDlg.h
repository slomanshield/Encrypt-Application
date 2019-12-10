#pragma once
#include "afxwin.h"


// CreateKeyDatabaseDlg dialog

class CreateKeyDatabaseDlg : public CDialog
{
	DECLARE_DYNAMIC(CreateKeyDatabaseDlg)

public:
	CreateKeyDatabaseDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CreateKeyDatabaseDlg();
	BOOL OnInitDialog();

// Dialog Data
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
private:
	CEdit password;
	CButton passwordChkBox;
	CButton password_hardwareChkBox;
public:
	afx_msg void OnBnClickedPassword();
	afx_msg void OnBnClickedPasswordHardware();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedCreateDatabase();
};

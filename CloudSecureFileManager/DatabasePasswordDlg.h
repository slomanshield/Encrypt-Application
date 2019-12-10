#pragma once
#include "afxwin.h"


// DatabasePasswordDlg dialog

class DatabasePasswordDlg : public CDialog
{
	DECLARE_DYNAMIC(DatabasePasswordDlg)

public:
	DatabasePasswordDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~DatabasePasswordDlg();
	BOOL PreTranslateMessage(MSG* pMsg);
// Dialog Data
	enum { IDD = IDD_PASSWORD };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedPasswordSubmit();
	CEdit passwordEdit;
private:
	void LoginUser();
};

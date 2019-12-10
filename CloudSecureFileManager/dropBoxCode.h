#pragma once
#include "afxwin.h"


// dropBoxCode dialog

class dropBoxCode : public CDialog
{
	DECLARE_DYNAMIC(dropBoxCode)

public:
	dropBoxCode(CWnd* pParent = NULL);   // standard constructor
	virtual ~dropBoxCode();

// Dialog Data
	enum { IDD = IDD_DROPBOX_CODE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	CEdit codeEditCtrl;
private:
	BOOL PreTranslateMessage(MSG* pMsg);
};

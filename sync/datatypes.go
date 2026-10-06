package sync

import "strconv"

const (
	SYNC_TYPE_AUTOFILL                 = 31729
	SYNC_TYPE_THEME                    = 41210
	SYNC_TYPE_TYPED_URL                = 40781
	SYNC_TYPE_NIGORI                   = 47745
	SYNC_TYPE_APP                      = 48364
	SYNC_TYPE_SESSION                  = 50119
	SYNC_TYPE_AUTOFILL_PROFILE         = 63951
	SYNC_TYPE_SEARCH_ENGINE            = 88610
	SYNC_TYPE_APP_SETTING              = 103656
	SYNC_TYPE_HISTORY_DELETE_DIRECTIVE = 150251
	SYNC_TYPE_PRIORITY_PREFERENCE      = 163425
	SYNC_TYPE_DICTIONARY               = 170540
	SYNC_TYPE_APP_LIST                 = 229170
	SYNC_TYPE_AUTOFILL_WALLET          = 306270
	SYNC_TYPE_WALLET_METADATA          = 330441
	SYNC_TYPE_PRINTER                  = 410745
	SYNC_TYPE_READING_LIST             = 411028
	SYNC_TYPE_USER_EVENT               = 455206
	SYNC_TYPE_USER_CONSENT             = 556014
	SYNC_TYPE_SECURITY_EVENT           = 600372
	SYNC_TYPE_SEND_TAB_TO_SELF         = 601980
	SYNC_TYPE_WIFI_CONFIGURATION       = 662827
	SYNC_TYPE_WEB_APP                  = 673225
	SYNC_TYPE_OS_PREFERENCE            = 702141
	SYNC_TYPE_OS_PRIORITY_PREFERENCE   = 703915
	SYNC_TYPE_SHARING_MESSAGE          = 728866
	SYNC_TYPE_AUTOFILL_OFFER           = 774329
	SYNC_TYPE_WORKSPACE_DESK           = 874841
	SYNC_TYPE_WEBAUTHN_CREDENTIAL      = 895275
	SYNC_TYPE_EDGE_E_DROP              = 956368
	SYNC_TYPE_PRINTERS_AUTH_SERVER     = 974304
	SYNC_TYPE_SAVED_TAB_GROUP          = 1004874
	SYNC_TYPE_AUTOFILL_WALLET_USAGE    = 1033580
	SYNC_TYPE_CONTACT_INFO             = 1034378
	SYNC_TYPE_INCOMING_PW_SHARING_INV  = 1141935
	SYNC_TYPE_OUTGOING_PW_SHARING_INV  = 1142081
	SYNC_TYPE_AUTOFILL_WALLET_CRED     = 1164238
	SYNC_TYPE_SHARED_TAB_GROUP_DATA    = 1239418
	SYNC_TYPE_COLLABORATION_GROUP      = 1259076
	SYNC_TYPE_PLUS_ADDRESS             = 1267844
	SYNC_TYPE_COOKIE                   = 1281100
	SYNC_TYPE_PLUS_ADDRESS_SETTING     = 1303742
	SYNC_TYPE_PRODUCT_COMPARISON       = 1329438
	SYNC_TYPE_AUTOFILL_VALUABLE        = 1419865
	SYNC_TYPE_SHARED_TAB_GROUP_ACCOUNT = 1429255
	SYNC_TYPE_ACCOUNT_SETTING          = 1438954
	SYNC_TYPE_SKILL                    = 1564245

	SYNC_TYPE_EDGE_AUTOFILL_FORM_FIELD = 1105252
	SYNC_TYPE_MANAGED_USER_SETTING     = 186662
	SYNC_TYPE_ARC_PACKAGE              = 340906
	SYNC_TYPE_AUTOFILL_VALUABLE_META   = 1520954
	SYNC_TYPE_SHARED_COMMENT           = 1484017
	SYNC_TYPE_AI_THREAD                = 1517585
	SYNC_TYPE_CONTEXTUAL_TASK          = 1518931
	SYNC_TYPE_GEMINI_THREAD            = 1569348
	SYNC_TYPE_THEME_IOS                = 1577986
	SYNC_TYPE_THEME_ANDROID            = 1587331
	SYNC_TYPE_COLLECTION               = 650913
	SYNC_TYPE_COLLECTIONS_METADATA     = 654917
	SYNC_TYPE_EDGE_WALLET              = 1125685
	SYNC_TYPE_EDGE_HUB_APP_USAGE       = 1308713
	SYNC_TYPE_EDGE_WORKSPACE           = 1902948
	SYNC_TYPE_EDGE_JOURNEY             = 1548704
)

var dataTypeNames = map[uint64]string{
	1:                     "Encrypted",
	SYNC_TYPE_AUTOFILL:    "Autofill",
	SYNC_TYPE_BOOKMARKS:   "Bookmarks",
	SYNC_TYPE_PREFERENCE:  "Preferences",
	SYNC_TYPE_THEME:       "Theme",
	SYNC_TYPE_TYPED_URL:   "TypedURL",
	SYNC_TYPE_PASSWORDS:   "Passwords",
	SYNC_TYPE_NIGORI:      "Nigori",
	SYNC_TYPE_EXTENSIONS:  "Extensions",
	SYNC_TYPE_APP:         "App",
	SYNC_TYPE_SESSION:     "Sessions",
	SYNC_TYPE_AUTOFILL_PROFILE:         "AutofillProfile",
	SYNC_TYPE_SEARCH_ENGINE:            "SearchEngine",
	SYNC_TYPE_EXTENSION_SETTINGS:       "ExtensionSettings",
	SYNC_TYPE_APP_SETTING:              "AppSetting",
	SYNC_TYPE_HISTORY_DELETE_DIRECTIVE: "HistoryDeleteDirective",
	SYNC_TYPE_DEVICE:                   "DeviceInfo",
	SYNC_TYPE_PRIORITY_PREFERENCE:      "PriorityPreference",
	SYNC_TYPE_DICTIONARY:               "Dictionary",
	SYNC_TYPE_APP_LIST:                 "AppList",
	SYNC_TYPE_AUTOFILL_WALLET:          "AutofillWallet",
	SYNC_TYPE_WALLET_METADATA:          "WalletMetadata",
	SYNC_TYPE_PRINTER:                  "Printer",
	SYNC_TYPE_READING_LIST:             "ReadingList",
	SYNC_TYPE_USER_EVENT:               "UserEvent",
	SYNC_TYPE_USER_CONSENT:             "UserConsent",
	SYNC_TYPE_SECURITY_EVENT:           "SecurityEvent",
	SYNC_TYPE_SEND_TAB_TO_SELF:         "SendTabToSelf",
	SYNC_TYPE_WIFI_CONFIGURATION:       "WifiConfiguration",
	SYNC_TYPE_WEB_APP:                  "WebApp",
	SYNC_TYPE_OS_PREFERENCE:            "OsPreference",
	SYNC_TYPE_OS_PRIORITY_PREFERENCE:   "OsPriorityPreference",
	SYNC_TYPE_SHARING_MESSAGE:          "SharingMessage",
	SYNC_TYPE_AUTOFILL_OFFER:           "AutofillOffer",
	SYNC_TYPE_WORKSPACE_DESK:           "WorkspaceDesk",
	SYNC_TYPE_WEBAUTHN_CREDENTIAL:      "WebauthnCredential",
	SYNC_TYPE_EDGE_E_DROP:              "EdgeEDrop",
	SYNC_TYPE_PRINTERS_AUTH_SERVER:     "PrintersAuthorizationServer",
	SYNC_TYPE_SAVED_TAB_GROUP:          "SavedTabGroup",
	SYNC_TYPE_AUTOFILL_WALLET_USAGE:    "AutofillWalletUsage",
	SYNC_TYPE_CONTACT_INFO:             "ContactInfo",
	SYNC_TYPE_INCOMING_PW_SHARING_INV:  "IncomingPasswordSharingInvitation",
	SYNC_TYPE_OUTGOING_PW_SHARING_INV:  "OutgoingPasswordSharingInvitation",
	SYNC_TYPE_AUTOFILL_WALLET_CRED:     "AutofillWalletCredential",
	SYNC_TYPE_SHARED_TAB_GROUP_DATA:    "SharedTabGroupData",
	SYNC_TYPE_COLLABORATION_GROUP:      "CollaborationGroup",
	SYNC_TYPE_PLUS_ADDRESS:             "PlusAddress",
	SYNC_TYPE_COOKIE:                   "Cookie",
	SYNC_TYPE_PLUS_ADDRESS_SETTING:     "PlusAddressSetting",
	SYNC_TYPE_PRODUCT_COMPARISON:       "ProductComparison",
	SYNC_TYPE_AUTOFILL_VALUABLE:        "AutofillValuable",
	SYNC_TYPE_SHARED_TAB_GROUP_ACCOUNT: "SharedTabGroupAccountData",
	SYNC_TYPE_ACCOUNT_SETTING:          "AccountSetting",
	SYNC_TYPE_HISTORY:                  "History",
	SYNC_TYPE_SKILL:                    "Skill",

	SYNC_TYPE_EDGE_AUTOFILL_FORM_FIELD: "Edge Autofill Form Field Data",
	SYNC_TYPE_MANAGED_USER_SETTING:     "Managed User Settings",
	SYNC_TYPE_ARC_PACKAGE:              "Arc Package",
	SYNC_TYPE_AUTOFILL_VALUABLE_META:   "Autofill Valuable Metadata",
	SYNC_TYPE_SHARED_COMMENT:           "SharedComment",
	SYNC_TYPE_AI_THREAD:                "AI Thread",
	SYNC_TYPE_CONTEXTUAL_TASK:          "Contextual Task",
	SYNC_TYPE_GEMINI_THREAD:            "Gemini Thread",
	SYNC_TYPE_THEME_IOS:                "Themes (iOS)",
	SYNC_TYPE_THEME_ANDROID:            "Themes (Android)",
	SYNC_TYPE_COLLECTION:               "Collection",
	SYNC_TYPE_COLLECTIONS_METADATA:     "Collections Metadata",
	SYNC_TYPE_EDGE_WALLET:              "Edge Wallet",
	SYNC_TYPE_EDGE_HUB_APP_USAGE:       "Edge Hub App Usage",
	SYNC_TYPE_EDGE_WORKSPACE:           "Edge Workspace",
	SYNC_TYPE_EDGE_JOURNEY:             "Edge Journey",
}

func DataTypeName(field uint64) string {
	if n, ok := dataTypeNames[field]; ok {
		return n
	}
	return "Unknown"
}

var osTypeNames = map[int32]string{
	0: "Unspecified",
	1: "Windows",
	2: "macOS",
	3: "Linux",
	4: "ChromeOS",
	5: "Android",
	6: "iOS",
	7: "Fuchsia",
}

func OsTypeName(t int32) string {
	if n, ok := osTypeNames[t]; ok {
		return n
	}
	return "Unknown(" + strconv.Itoa(int(t)) + ")"
}

func AllDataTypeCodes() []int32 {
	codes := make([]int32, 0, len(dataTypeNames))
	for f := range dataTypeNames {
		if f == 1 {
			continue
		}
		codes = append(codes, int32(f))
	}
	return codes
}

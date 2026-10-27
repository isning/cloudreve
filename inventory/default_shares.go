package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/predicate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/ent/share"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
)

const DefaultSharesSetting = "default_symbolics"
const DefaultShareIdentityMetadata = "sys:default_share_identity"
const defaultSharesIdentitiesSetting = "default_symbolics_identities"
const defaultShareRedirect = "sys:shared_redirect"

var errInvalidDefaultShareConfiguration = errors.New("invalid stored default shares")

// ParseDefaultShares accepts the existing numeric dashboard ID wire format.
func ParseDefaultShares(raw string) ([]int, error) {
	var ids []int
	if len(raw) > 8192 || json.Unmarshal([]byte(raw), &ids) != nil || ids == nil || len(ids) > 100 {
		return nil, errors.New("expected at most 100 positive share IDs")
	}
	out := make([]int, 0, len(ids))
	seen := map[int]bool{}
	for _, id := range ids {
		if id <= 0 || uint64(id) > 9007199254740991 {
			return nil, errors.New("invalid share ID")
		}
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out, nil
}

func defaultShareRefs(ctx context.Context, c *ent.Client) ([]types.DefaultShareRef, error) {
	// Fetch list and incarnation bindings in one statement: account creation
	// must never capture a torn configuration during an administrator save.
	rows, err := c.Setting.Query().Where(setting.NameIn(DefaultSharesSetting, defaultSharesIdentitiesSetting), permissionRead(ctx)).All(ctx)
	if err != nil {
		return nil, err
	}
	raw := "[]"
	identityRaw := ""
	for _, row := range rows {
		if row.Name == DefaultSharesSetting {
			raw = row.Value
		} else {
			identityRaw = row.Value
		}
	}
	ids, err := ParseDefaultShares(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidDefaultShareConfiguration, err)
	}
	refs := make([]types.DefaultShareRef, 0, len(ids))
	stored := map[int]types.DefaultShareRef{}
	if identityRaw != "" {
		var values []types.DefaultShareRef
		if err := json.Unmarshal([]byte(identityRaw), &values); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidDefaultShareConfiguration, err)
		}
		for _, ref := range values {
			stored[ref.ID] = ref
		}
	}
	for _, id := range ids {
		if ref, ok := stored[id]; ok {
			refs = append(refs, ref)
			continue
		}
		ref := types.DefaultShareRef{ID: id}
		live, e := c.Share.Get(ctx, id)
		if e != nil && !ent.IsNotFound(e) {
			return nil, e
		}
		if live != nil {
			ref.CreatedAt = live.CreatedAt
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func captureDefaultShares(ctx context.Context, c *ent.Client, settings *types.UserSetting) error {
	refs, err := defaultShareRefs(ctx, c)
	if err != nil {
		return err
	}
	settings.DefaultShares = &types.DefaultShareState{Shares: refs}
	return nil
}

// SaveDefaultShares runs in the settings transaction. Existing stale selections
// can be retained, but new selections must resolve to a valid source.
func SaveDefaultShares(ctx context.Context, c *ent.Client, raw string) (string, error) {
	ids, err := ParseDefaultShares(raw)
	if err != nil {
		return "", serializer.NewError(serializer.CodeParamErr, "Invalid default shares", nil)
	}
	// A caller may already hold source-owner locks from creating a pending
	// share. Acquire all candidate owners before the configuration fence, as
	// explicit installation does, before any current source reads.
	planned := make(map[int]bool, len(ids))
	if len(ids) > 0 {
		links, err := sharePermissionMetadata(ctx, NewSettingClient(c, nil), true, ids...)
		if err != nil {
			return "", err
		}
		var owners []int
		for _, link := range links {
			planned[link.ID] = true
			if link.Edges.User != nil {
				owners = append(owners, link.Edges.User.ID)
			}
			if link.Edges.File != nil {
				owners = append(owners, link.Edges.File.OwnerID)
			}
		}
		if err := lockDefaultShareOwners(ctx, c, owners...); err != nil {
			return "", err
		}
	}
	// Configuration writers and explicit installation share this fence.
	if err := c.Setting.Create().SetName(DefaultSharesSetting).SetValue("[]").OnConflictColumns(setting.FieldName).Ignore().Exec(ctx); err != nil {
		return "", err
	}
	if tx := permissionOwnerTransaction(ctx); tx != nil {
		tx.defaultShareConfigurationLocked = true
	}
	if err := c.Setting.Update().Where(setting.Name(DefaultSharesSetting)).SetName(DefaultSharesSetting).Exec(ctx); err != nil {
		return "", err
	}
	currentCtx := context.WithValue(ctx, CurrentPermissionReadCtx{}, true)
	oldRefs, err := defaultShareRefs(currentCtx, c)
	if err != nil && !errors.Is(err, errInvalidDefaultShareConfiguration) {
		return "", err
	}
	// An invalid legacy value can be replaced, but cannot exempt any new
	// selection from live validation. Database failures still abort the save.
	references := map[int]types.DefaultShareRef{}
	for _, ref := range oldRefs {
		references[ref.ID] = ref
	}
	for _, id := range ids {
		if _, retained := references[id]; retained {
			continue
		}
		if !planned[id] {
			return "", serializer.NewError(serializer.CodeParamErr, "Default share is unavailable", nil)
		}
		s, err := loadDefaultShare(currentCtx, c, id)
		if err != nil && !ent.IsNotFound(err) {
			return "", err
		}
		if err != nil || IsValidShare(s) != nil {
			return "", serializer.NewError(serializer.CodeParamErr, "Default share is unavailable", nil)
		}
		references[id] = types.DefaultShareRef{ID: id, CreatedAt: s.CreatedAt}
		if err := ValidateShareSource(currentCtx, c, s.Edges.File, nil); err != nil {
			if errors.Is(err, ErrSourceFileInvalid) {
				return "", serializer.NewError(serializer.CodeParamErr, "Default share is unavailable", nil)
			}
			return "", err
		}
	}
	nextRefs := make([]types.DefaultShareRef, 0, len(ids))
	for _, id := range ids {
		nextRefs = append(nextRefs, references[id])
	}
	encodedRefs, _ := json.Marshal(nextRefs)
	if err := c.Setting.Create().SetName(defaultSharesIdentitiesSetting).SetValue(string(encodedRefs)).OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx); err != nil {
		return "", err
	}
	normalized, _ := json.Marshal(ids)
	err = c.Setting.Create().SetName(DefaultSharesSetting).SetValue(string(normalized)).OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx)
	return string(normalized), err
}

// A pending source may already retain higher owner locks. Reject an incomplete
// composition fence before waiting, so the caller can retain or roll back its
// work and retry with the complete owner union acquired before source creation.
func lockDefaultShareOwners(ctx context.Context, c *ent.Client, ids ...int) error {
	held := permissionOwnerLocks(ctx)
	highest := 0
	for id := range held {
		highest = max(highest, id)
	}
	for _, id := range ids {
		if id > 0 && id < highest && !held[id] {
			return defaultShareOwnerConflict()
		}
	}
	return LockPermissionOwners(ctx, c, ids...)
}

func defaultShareOwnerConflict() error {
	return serializer.NewError(serializer.CodeLockConflict, "Acquire all share owners before creating sources or saving configuration", nil)
}

func loadDefaultShare(ctx context.Context, c *ent.Client, id int) (*ent.Share, error) {
	return c.Share.Query().Where(share.ID(id), permissionRead(ctx)).
		WithUser(func(q *ent.UserQuery) { q.Where(permissionRead(ctx)) }).
		WithFile(func(q *ent.FileQuery) {
			q.Where(permissionRead(ctx)).WithOwner(func(q *ent.UserQuery) { q.Where(permissionRead(ctx)) })
		}).Only(ctx)
}

// defaultShareFiles plans primary keys without locking empty owner/name ranges.
// The owner fence is already held. Final batches use current transaction rows,
// while the two metadata views retain pending files and discover committed ones.
func defaultShareFiles(ctx context.Context, c *ent.Client, includeMetadata bool, conditions ...predicate.File) ([]*ent.File, error) {
	usesMySQL := false
	ids, err := c.File.Query().Where(conditions...).Where(func(s *sql.Selector) {
		usesMySQL = s.Dialect() == dialect.MySQL
	}).IDs(ctx)
	if err != nil {
		return nil, err
	}
	if usesMySQL {
		if committed := CommittedMetadataClient(ctx); committed != nil {
			latest, err := committed.File.Query().Where(conditions...).IDs(ctx)
			if err != nil {
				return nil, err
			}
			ids = append(ids, latest...)
		}
	}
	unique := make(map[int]bool, len(ids))
	for _, id := range ids {
		unique[id] = true
	}
	ids = ids[:0]
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var files []*ent.File
	for offset := 0; offset < len(ids); offset += 500 {
		query := c.File.Query().Where(conditions...).Where(file.IDIn(ids[offset:min(offset+500, len(ids))]...), CurrentPermissionRead)
		if includeMetadata {
			query.WithMetadata(func(q *ent.MetadataQuery) { q.Where(CurrentPermissionRead) })
		}
		batch, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		files = append(files, batch...)
	}
	return files, nil
}

// DefaultShareIdentity binds a shortcut to an incarnation, not a reusable ID.
func DefaultShareIdentity(s *ent.Share) string {
	return strconv.Itoa(s.ID) + ":" + s.CreatedAt.UTC().Format(time.RFC3339Nano)
}

type DefaultShareResult struct {
	Files    []*ent.File `json:"-"`
	Added    int         `json:"added"`
	Existing int         `json:"existing"`
	Skipped  int         `json:"skipped"`
}

// InstallDefaultShares owns the personal root and shortcut transaction. The
// automatic mode consumes the account snapshot once; explicit mode uses the
// current list and never changes automatic eligibility.
func InstallDefaultShares(ctx context.Context, uc UserClient, uid int, h hashid.Encoder, current bool) (*ent.File, *DefaultShareResult, error) {
	uc, _ = InheritTx(ctx, uc)
	// Read candidate owner IDs before beginning the write transaction, so all
	// authorization reads inside it follow the owner fences on every dialect.
	planningCtx := context.WithValue(ctx, CurrentPermissionReadCtx{}, false)
	// Candidate reads only plan the complete owner fence. Current validation
	// below decides the effective list, including pending caller configuration.
	usesMySQL := false
	candidate, err := uc.GetClient().User.Query().Where(user.ID(uid), func(s *sql.Selector) {
		usesMySQL = s.Dialect() == dialect.MySQL
	}).Only(planningCtx)
	if ent.IsNotFound(err) && usesMySQL {
		if committed := CommittedMetadataClient(ctx); committed != nil {
			candidate, err = committed.User.Get(planningCtx, uid)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	var refs []types.DefaultShareRef
	if current {
		configurationLocked := false
		if tx := permissionOwnerTransaction(ctx); tx != nil {
			configurationLocked = tx.defaultShareConfigurationLocked
		}
		configurationCtx := planningCtx
		if configurationLocked {
			// The caller already fences this configuration. Its current pending
			// list alone decides which owners are needed; committed metadata
			// may still contain an unrelated configuration it has replaced.
			configurationCtx = context.WithValue(ctx, CurrentPermissionReadCtx{}, true)
		}
		refs, err = defaultShareRefs(configurationCtx, uc.GetClient())
		if err != nil && !errors.Is(err, errInvalidDefaultShareConfiguration) {
			return nil, nil, err
		}
		if usesMySQL && !configurationLocked {
			if committed := CommittedMetadataClient(ctx); committed != nil {
				latest, e := defaultShareRefs(planningCtx, committed)
				if e != nil && !errors.Is(e, errInvalidDefaultShareConfiguration) {
					return nil, nil, e
				}
				refs = append(refs, latest...)
			}
		}
	} else if candidate.Settings != nil && candidate.Settings.DefaultShares != nil && !candidate.Settings.DefaultShares.Done {
		refs = candidate.Settings.DefaultShares.Shares
	}
	owners := []int{uid}
	var links []*ent.Share
	var missing []int
	for _, ref := range refs {
		s, e := loadDefaultShare(planningCtx, uc.GetClient(), ref.ID)
		if ent.IsNotFound(e) {
			missing = append(missing, ref.ID)
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		links = append(links, s)
	}
	if len(missing) > 0 {
		latest, e := sharePermissionMetadata(planningCtx, uc, true, missing...)
		if e != nil {
			return nil, nil, e
		}
		links = append(links, latest...)
	}
	for _, s := range links {
		if s.Edges.User != nil {
			owners = append(owners, s.Edges.User.ID)
		}
		if s.Edges.File != nil {
			owners = append(owners, s.Edges.File.OwnerID)
		}
	}
	tc, tx, ctx, err := WithTx(ctx, uc)
	if err != nil {
		return nil, nil, err
	}
	defer Rollback(tx)
	c := tc.GetClient()
	if current {
		err = lockDefaultShareOwners(ctx, c, owners...)
	} else {
		err = LockPermissionOwners(ctx, c, owners...)
	}
	if err != nil {
		return nil, nil, err
	}
	// Settings writers acquire this row before touching this configuration.
	// Serialize explicit installation with removal from the current list.
	if current {
		if err = c.Setting.Update().Where(setting.Name(DefaultSharesSetting)).SetName(DefaultSharesSetting).Exec(ctx); err != nil {
			return nil, nil, err
		}
		if tx := permissionOwnerTransaction(ctx); tx != nil {
			tx.defaultShareConfigurationLocked = true
		}
	}
	ctx = context.WithValue(ctx, CurrentPermissionReadCtx{}, true)
	actor, err := tc.GetByID(context.WithValue(ctx, LoadUserGroup{}, true), uid)
	if err != nil {
		return nil, nil, err
	}
	if current && actor.Status != user.StatusActive {
		return nil, nil, PermissionDenied(types.FilePermissionList)
	}
	if actor.Settings == nil {
		actor.Settings = &types.UserSetting{}
	}
	state := actor.Settings.DefaultShares
	if !current {
		if actor.Status != user.StatusActive || state == nil || state.Done {
			refs = nil
		} else {
			refs = state.Shares
		}
	} else {
		latest, e := defaultShareRefs(ctx, c)
		if e != nil {
			return nil, nil, e
		}
		allowed := map[string]bool{}
		for _, r := range refs {
			allowed[fmt.Sprint(r.ID)+":"+r.CreatedAt.UTC().Format(time.RFC3339Nano)] = true
		}
		filtered := latest[:0]
		for _, r := range latest {
			if allowed[fmt.Sprint(r.ID)+":"+r.CreatedAt.UTC().Format(time.RFC3339Nano)] {
				filtered = append(filtered, r)
			}
		}
		refs = filtered
	}
	roots, err := defaultShareFiles(ctx, c, false, file.OwnerID(uid), file.Not(file.HasParent()), file.Name(RootFolderName))
	if err != nil {
		return nil, nil, err
	}
	var root *ent.File
	switch len(roots) {
	case 0:
		root, err = c.File.Create().SetOwnerID(uid).SetType(int(types.FileTypeFolder)).SetName(RootFolderName).Save(ctx)
	case 1:
		root = roots[0]
	default:
		return nil, nil, errors.New("multiple personal roots")
	}
	if err != nil {
		return nil, nil, err
	}
	result := &DefaultShareResult{}
	existing := map[string]bool{}
	if len(refs) > 0 {
		shortcuts, e := defaultShareFiles(ctx, c, true, file.OwnerID(uid), file.IsSymbolic(true))
		if e != nil {
			return nil, nil, e
		}
		ancestors := map[int]*ent.File{root.ID: root}
		for _, shortcut := range shortcuts {
			if e := ValidateShareSource(ctx, c, shortcut, ancestors); errors.Is(e, ErrSourceFileInvalid) {
				continue
			} else if e != nil {
				return nil, nil, e
			}
			for _, m := range shortcut.Edges.Metadata {
				if m.Name == defaultShareRedirect {
					parsed, parseErr := url.Parse(m.Value)
					if parseErr == nil && parsed.Scheme == "cloudreve" && strings.ToLower(parsed.Host) == "share" && parsed.User != nil {
						identity := parsed.Query().Get("default_share_identity")
						if identity == "" {
							for _, meta := range shortcut.Edges.Metadata {
								if meta.Name == DefaultShareIdentityMetadata {
									identity = meta.Value
								}
							}
						}
						if identity == "" {
							existing[parsed.User.Username()] = true
						} else {
							existing[identity] = true
						}
					}
				}
			}
		}
	}
	for _, ref := range refs {
		s, e := loadDefaultShare(ctx, c, ref.ID)
		if ent.IsNotFound(e) {
			result.Skipped++
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		if !s.CreatedAt.Equal(ref.CreatedAt) || IsValidShare(s) != nil {
			result.Skipped++
			continue
		}
		// The lock set was established from the same immutable share incarnation.
		locked := func(id int) bool {
			for _, owner := range owners {
				if owner == id {
					return true
				}
			}
			return false
		}
		if !locked(s.Edges.File.OwnerID) || !locked(s.Edges.User.ID) {
			result.Skipped++
			continue
		}
		if e = ValidateShareSource(ctx, c, s.Edges.File, nil); errors.Is(e, ErrSourceFileInvalid) {
			result.Skipped++
			continue
		} else if e != nil {
			return nil, nil, e
		}
		grant := ResolveSharePermission(s, actor, s.Edges.File.Edges.Owner, h)
		readable := CheckShareAccess(s, actor) == nil && (grant.Enabled(int(types.FilePermissionRead)) || grant.Enabled(int(types.FilePermissionList)))
		if current && (s.Password != "" || !readable) {
			result.Skipped++
			continue
		}
		shareID := hashid.EncodeShareID(h, s.ID)
		identity := DefaultShareIdentity(s)
		redirect := "cloudreve://" + shareID + "@share"
		shortcutType := int(types.FileTypeFolder)
		if readable && s.Password == "" && s.Edges.File.Type == int(types.FileTypeFile) {
			shortcutType = int(types.FileTypeFile)
			redirect += "/" + url.PathEscape(s.Edges.File.Name)
		}
		redirect += "?default_share_identity=" + url.QueryEscape(identity)
		if existing[shareID] || existing[identity] {
			result.Existing++
			continue
		}
		name := "Shared resource"
		if readable && s.Password == "" {
			name = s.Edges.File.Name
		}
		name = strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < ' ' || strings.ContainsRune("/\\:*?\"<>|", r) {
				return '_'
			}
			return r
		}, name))
		if name == "" || name == "." || name == ".." {
			name = "Shared resource"
		}
		for len(name) > 220 {
			runes := []rune(name)
			name = string(runes[:len(runes)-1])
		}
		base := name
		for n := 1; ; n++ {
			matches, e := defaultShareFiles(ctx, c, false, file.FileChildren(root.ID), file.Name(name))
			if e != nil {
				return nil, nil, e
			}
			if len(matches) == 0 {
				break
			}
			name = fmt.Sprintf("%s (%d)", base, n)
		}
		shortcut, e := c.File.Create().SetOwnerID(uid).SetParent(root).SetType(shortcutType).SetName(name).SetIsSymbolic(true).Save(ctx)
		if e != nil {
			return nil, nil, e
		}
		for key, value := range map[string]string{defaultShareRedirect: redirect, "sys:shared_owner": hashid.EncodeUserID(h, s.Edges.User.ID), DefaultShareIdentityMetadata: DefaultShareIdentity(s)} {
			if e = c.Metadata.Create().SetFile(shortcut).SetName(key).SetValue(value).SetIsPublic(true).Exec(ctx); e != nil {
				return nil, nil, e
			}
		}
		existing[identity] = true
		result.Added++
		result.Files = append(result.Files, shortcut)
		auditActor := UserFromContext(ctx)
		if auditActor == nil || IsAnonymousUser(auditActor) {
			auditActor = actor
		}
		if e = RecordAudit(ctx, c, AuditEvent{Type: types.AuditMount, User: auditActor, FileID: shortcut.ID, Content: types.LogEntry{Name: name, From: "cloudreve://" + hashid.EncodeUserID(h, uid) + "@my/" + url.PathEscape(name)}}); e != nil {
			return nil, nil, e
		}
	}
	if !current && actor.Status == user.StatusActive && state != nil && !state.Done {
		state.Done = true
		if err = c.User.UpdateOneID(uid).SetSettings(actor.Settings).Exec(ctx); err != nil {
			return nil, nil, err
		}
	}
	if err = Commit(tx); err != nil {
		return nil, nil, err
	}
	return root, result, nil
}

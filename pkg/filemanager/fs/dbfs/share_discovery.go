package dbfs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
)

// A request bounds candidate work even when almost every link is denied.
const shareDiscoveryBudget = 1000

type discoveryCursor struct {
	Context string `json:"c"`
	Last    string `json:"l"`
}

func (n *sharedWithMeNavigator) cursorMAC(raw []byte) []byte {
	m := hmac.New(sha256.New, []byte("share-discovery/v1/"+n.cursorKey))
	m.Write(raw)
	return m.Sum(nil)
}
func (n *sharedWithMeNavigator) discoveryContext(args *ListArgs) string {
	raw, _ := json.Marshal(struct {
		User                   int
		Mode, Order, Direction string
		Search                 *inventory.SearchFileParameters
	}{
		n.user.ID, "acl", args.Page.OrderBy, string(args.Page.Order), args.Search,
	})
	return base64.RawURLEncoding.EncodeToString(n.cursorMAC(raw))
}
func (n *sharedWithMeNavigator) readDiscoveryCursor(args *ListArgs) (string, error) {
	token := args.Page.PageToken
	if token == "" {
		return "", nil
	}
	invalid := serializer.NewError(serializer.CodeParamErr, "Invalid share discovery cursor", nil)
	if len(token) > 4096 {
		return "", invalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", invalid
	}
	aead := n.discoveryCipher()
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return "", invalid
	}
	raw, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte("cloudreve/share-discovery/v1"))
	if err != nil {
		return "", invalid
	}
	var cursor discoveryCursor
	if json.Unmarshal(raw, &cursor) != nil || cursor.Context != n.discoveryContext(args) {
		return "", invalid
	}
	return cursor.Last, nil
}
func (n *sharedWithMeNavigator) discoveryCipher() cipher.AEAD {
	key := sha256.Sum256([]byte("share-discovery/v1/" + n.cursorKey))
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	return aead
}
func (n *sharedWithMeNavigator) writeDiscoveryCursor(args *ListArgs, last string) (string, error) {
	if last == "" {
		return "", nil
	}
	raw, _ := json.Marshal(discoveryCursor{n.discoveryContext(args), last})
	aead := n.discoveryCipher()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, raw, []byte("cloudreve/share-discovery/v1"))), nil
}

func (n *sharedWithMeNavigator) discoverShares(ctx context.Context, args *ListArgs) (*ListResult, error) {
	if args.Page.OrderBy == "" {
		args.Page.OrderBy = "created_at"
	}
	if args.Page.Order == "" {
		args.Page.Order = inventory.OrderDirectionAsc
	}
	token, err := n.readDiscoveryCursor(args)
	if err != nil {
		return nil, err
	}
	if args.Page.OrderBy != "name" && args.Page.OrderBy != "created_at" || args.Page.Order != inventory.OrderDirectionAsc && args.Page.Order != inventory.OrderDirectionDesc {
		return nil, serializer.NewError(serializer.CodeParamErr, "Unsupported share discovery order", nil)
	}
	if search := args.Search; search != nil && (len(search.Metadata) > 0 || search.UseFullText || search.Category != "" || search.SizeGte != 0 || search.SizeLte != 0 || search.CreatedAtGte != nil || search.CreatedAtLte != nil || search.UpdatedAtGte != nil || search.UpdatedAtLte != nil) {
		return nil, serializer.NewError(serializer.CodeParamErr, "This search is not supported in share discovery", nil)
	}
	ctx = context.WithValue(ctx, inventory.LoadShareUser{}, true)
	ctx = context.WithValue(ctx, inventory.LoadShareFile{}, true)
	ctx = context.WithValue(ctx, inventory.LoadUserGroup{}, true)
	// The virtual parent is owned by the viewer, but its listing flags must
	// never load every other link/entity attached to each candidate source.
	ctx = context.WithValue(ctx, inventory.LoadFileShare{}, false)
	ctx = context.WithValue(ctx, inventory.LoadFileDirectLink{}, false)
	ctx = context.WithValue(ctx, inventory.LoadFileEntity{}, false)
	ctx = context.WithValue(ctx, inventory.LoadFileMetadata{}, false)
	ctx = context.WithValue(ctx, inventory.LoadFilePublicMetadata{}, false)
	out := &ListResult{Files: []*File{}, MixedType: true, Pagination: &inventory.PaginationResults{PageSize: args.Page.PageSize, IsCursor: true}}
	ancestors := make(map[int]*ent.File)
	scanned := 0
	next := ""
	for scanned < shareDiscoveryBudget && len(out.Files) < args.Page.PageSize {
		size := min(100, shareDiscoveryBudget-scanned)
		batch, err := n.shareClient.List(ctx, &inventory.ListShareArgs{PaginationArgs: &inventory.PaginationArgs{
			UseCursorPagination: true, PageSize: size, PageToken: token, Order: args.Page.Order, OrderBy: args.Page.OrderBy,
		}, Discovery: true, Search: args.Search})
		if err != nil {
			return nil, serializer.NewError(serializer.CodeDBError, "Failed to list accessible shares", nil)
		}
		next = ""
		for i, s := range batch.Shares {
			scanned++
			// Use the last inspected candidate, including rejected links.
			last, _ := inventory.ShareDiscoveryPageToken(n.hasher, s, args.Page.OrderBy)
			if i < len(batch.Shares)-1 || batch.NextPageToken != "" {
				next = last
			} else {
				next = ""
			}
			if inventory.CheckShareAccess(s, n.user) != nil {
				continue
			}
			grant := inventory.ResolveSharePermission(s, n.user, s.Edges.File.Edges.Owner, n.hasher)
			if !grant.Enabled(int(types.FilePermissionRead)) && !grant.Enabled(int(types.FilePermissionList)) {
				continue
			}
			if err := inventory.ValidateShareSource(ctx, n.fileClient.GetClient(), s.Edges.File, ancestors); err != nil {
				if err == inventory.ErrSourceFileInvalid {
					continue
				}
				return nil, serializer.NewError(serializer.CodeDBError, "Failed to validate accessible shares", nil)
			}
			file := n.discoveredFile(s)
			n.virtualFiles = append(n.virtualFiles, file)
			out.Files = append(out.Files, file)
			if len(out.Files) >= args.Page.PageSize {
				break
			}
		}
		if len(out.Files) >= args.Page.PageSize || next == "" {
			break
		}
		token = next
	}
	out.Pagination.NextPageToken, err = n.writeDiscoveryCursor(args, next)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting, "Failed to create share discovery cursor", nil)
	}
	return out, nil
}

func (n *sharedWithMeNavigator) discoveredFile(s *ent.Share) *File {
	linkID := hashid.EncodeShareID(n.hasher, s.ID)
	identity := "share:" + linkID
	redirect := fs.NewShareUri(linkID, "")
	model := &ent.File{Name: s.Edges.File.Name, Type: int(types.FileTypeFolder), IsSymbolic: true, CreatedAt: s.CreatedAt, UpdatedAt: s.CreatedAt}
	model.Edges.Metadata = []*ent.Metadata{
		{Name: MetadataSharedRedirect, Value: redirect},
		{Name: MetadataSharedOwner, Value: hashid.EncodeUserID(n.hasher, s.Edges.User.ID)},
	}
	if s.Password != "" {
		model.Edges.Metadata = append(model.Edges.Metadata, &ent.Metadata{Name: "sys:shared_locked", Value: "1"})
	}
	file := newFile(nil, model)
	file.VirtualID = identity
	file.OwnerModel = s.Edges.User
	file.Path[pathIndexUser] = newSharedWithMeUri("").Join(identity)
	file.Path[pathIndexRoot] = file.Path[pathIndexUser]
	file.PermissionBs = &boolset.BooleanSet{1 << types.FilePermissionList}
	file.CapabilitiesBs = &boolset.BooleanSet{}
	boolset.Set(NavigatorCapabilityEnterFolder, true, file.CapabilitiesBs)
	return file
}

package types

import "time"

// RelocationReference records the selected association, independently of later
// copies or versions. It is private migration data, never a public task DTO.
type RelocationReference struct {
	FileID          int       `json:"file_id"`
	URI             string    `json:"uri,omitempty"`
	PrimaryEntityID int       `json:"primary_entity_id"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// RelocationSnapshot preserves the original entity identity and encryption
// metadata. Policy credentials and signed URLs are deliberately excluded.
type RelocationSnapshot struct {
	Type      int          `json:"type"`
	Size      int64        `json:"size"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	CreatedBy int          `json:"created_by"`
	Props     *EntityProps `json:"props,omitempty"`
}

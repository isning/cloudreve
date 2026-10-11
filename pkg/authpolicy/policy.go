// Package authpolicy derives local credential capabilities from account facts.
package authpolicy

import "fmt"

type Facts struct{ Managed, HasPassword, HasPasskey bool }
type Capabilities struct {
	PasswordUpdate  bool   `json:"password_update"`
	PasswordReset   bool   `json:"password_reset"`
	PasskeyRegister bool   `json:"passkey_register"`
	Reason          string `json:"reason,omitempty"`
}

func (f Facts) Capabilities() Capabilities {
	if f.Managed {
		return Capabilities{Reason: "managed"}
	}
	return Capabilities{PasswordUpdate: f.HasPassword, PasswordReset: true, PasskeyRegister: true}
}
func (f Facts) CheckLocalCredential() error {
	if f.Managed {
		return fmt.Errorf("managed account requires administrator release before local credentials can be established")
	}
	return nil
}
func (f Facts) PasswordLogin() bool { return !f.Managed && f.HasPassword }
func (f Facts) PasskeyLogin() bool  { return !f.Managed && f.HasPasskey }

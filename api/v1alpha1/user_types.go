package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// UserSpec defines the desired state of a Gate user.
type UserSpec struct {
	// UserName is the user identity mapped from SSH public keys.
	// +kubebuilder:validation:MinLength=1
	UserName string `json:"userName"`

	// PublicKeys is the list of allowed SSH public keys for the user.
	// +kubebuilder:validation:MinItems=1
	PublicKeys []string `json:"publicKeys"`

	// Enabled controls whether the user is permitted to authenticate.
	// +kubebuilder:default:=true
	Enabled *bool `json:"enabled,omitempty"`

	// Auth controls additional authentication requirements.
	Auth *UserAuthSpec `json:"auth,omitempty"`

	// OIDC binds the user to allowed OIDC identities/groups.
	OIDC *UserOIDCSpec `json:"oidc,omitempty"`
}

// UserAuthSpec defines optional authentication requirements.
type UserAuthSpec struct {
	// SSORequired enforces OIDC device-flow login in addition to SSH keys.
	SSORequired *bool `json:"ssoRequired,omitempty"`
}

// UserOIDCSpec defines allowed OIDC identities for this user.
type UserOIDCSpec struct {
	// Subjects is the list of allowed OIDC subject identifiers.
	// +kubebuilder:validation:MinItems=1
	Subjects []string `json:"subjects,omitempty"`

	// Groups is the list of allowed OIDC group names (exact match).
	Groups []string `json:"groups,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=gateuser
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=`.spec.userName`
// +kubebuilder:printcolumn:name="Enabled",type=string,JSONPath=`.spec.enabled`

// User is the Schema for the Gate users API.
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec UserSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// UserList contains a list of User.
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

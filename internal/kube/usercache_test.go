package kube

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"peertech.de/gate/api/v1alpha1"
)

func TestIndexUserNames(t *testing.T) {
	user := &v1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-one"},
		Spec: v1alpha1.UserSpec{
			UserName:   "alice",
			PublicKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"},
		},
	}

	cache := &UserCache{}
	userNames, err := cache.indexUserNames(user)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(userNames) != 1 {
		t.Fatalf("expected one user name, got %d", len(userNames))
	}
	if userNames[0] != "alice" {
		t.Fatalf("expected user name to be alice")
	}
}

func TestRevokedOnUpdate(t *testing.T) {
	disabled := false
	enabled := true

	oldUser := &v1alpha1.User{Spec: v1alpha1.UserSpec{Enabled: &enabled}}
	newUser := &v1alpha1.User{Spec: v1alpha1.UserSpec{Enabled: &disabled}}

	if !revokedOnUpdate(oldUser, newUser) {
		t.Fatalf("expected revoke when enabled flips to disabled")
	}

	oldUser = &v1alpha1.User{Spec: v1alpha1.UserSpec{Enabled: &disabled}}
	newUser = &v1alpha1.User{Spec: v1alpha1.UserSpec{Enabled: &disabled}}
	if revokedOnUpdate(oldUser, newUser) {
		t.Fatalf("expected no revoke when already disabled")
	}
}

func TestHandleRevocationInvokesHandler(t *testing.T) {
	user := &v1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-one"},
		Spec: v1alpha1.UserSpec{
			UserName:   "alice",
			PublicKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"},
		},
	}

	cache := &UserCache{}
	ch := make(chan UserRecord, 1)
	cache.SetRevokeHandler(func(record UserRecord) {
		ch <- record
	})

	cache.handleRevocation(user)

	select {
	case record := <-ch:
		if record.UserName != "alice" {
			t.Fatalf("expected user_name to be alice")
		}
	case <-time.After(time.Second):
		t.Fatalf("expected revoke handler to be called")
	}
}

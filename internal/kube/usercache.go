package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"peertech.de/gate/api/v1alpha1"
)

const (
	userNameIndex = "user_name"
)

var userGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  "v1alpha1",
	Resource: "users",
}

// ErrUserCacheNotReady indicates the User cache is not synced or healthy.
var ErrUserCacheNotReady = errors.New("user cache not ready")

// UserRecord is the cached view of a User CRD.
type UserRecord struct {
	Name            string
	UserName        string
	PublicKeys      []string
	Enabled         bool
	SSORequired     bool
	OIDCSubjects    []string
	OIDCGroups      []string
	ResourceVersion string
}

// UserCache provides lookup access for User CRDs via a shared informer.
type UserCache struct {
	informer cache.SharedIndexInformer
	logger   *slog.Logger
	stopCh   chan struct{}
	stopOnce sync.Once
	synced   atomic.Bool
	healthy  atomic.Bool
	mu       sync.RWMutex
	onRevoke func(UserRecord)
}

func NewUserCache(
	client dynamic.Interface,
	namespace string,
	resyncPeriod time.Duration,
	logger *slog.Logger,
) (*UserCache, error) {
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		client,
		resyncPeriod,
		namespace,
		nil,
	)
	informer := factory.ForResource(userGVR).Informer()

	userCache := &UserCache{
		informer: informer,
		logger:   logger,
	}

	if err := informer.AddIndexers(userCache.indexers()); err != nil {
		return nil, fmt.Errorf("add user cache indexers: %w", err)
	}

	informer.SetWatchErrorHandler(func(_ *cache.Reflector, err error) {
		userCache.healthy.Store(false)
		userCache.logger.Warn("user cache watch error", "error", err)
	})

	informer.AddEventHandler(userCache.eventHandler())

	return userCache, nil
}

// Start runs the informer and waits for initial sync.
func (c *UserCache) Start(ctx context.Context, syncTimeout time.Duration) error {
	if c.informer == nil {
		return ErrUserCacheNotReady
	}

	c.stopCh = make(chan struct{})
	go c.informer.Run(c.stopCh)

	waitCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	if !cache.WaitForCacheSync(waitCtx.Done(), c.informer.HasSynced) {
		return ErrUserCacheNotReady
	}

	c.synced.Store(true)
	c.healthy.Store(true)

	return nil
}

// Stop halts the informer.
func (c *UserCache) Stop() {
	if c.stopCh == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// Ready reports whether the cache is synced and healthy.
func (c *UserCache) Ready() bool {
	return c.synced.Load() && c.healthy.Load()
}

// SetRevokeHandler registers a callback invoked when a user is revoked or disabled.
func (c *UserCache) SetRevokeHandler(handler func(UserRecord)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onRevoke = handler
}

// LookupByUserName returns the first enabled user matching the user name.
func (c *UserCache) LookupByUserName(
	ctx context.Context,
	userName string,
) (UserRecord, bool, error) {
	if ctx.Err() != nil {
		return UserRecord{}, false, ctx.Err()
	}
	if !c.Ready() {
		return UserRecord{}, false, ErrUserCacheNotReady
	}

	objects, err := c.informer.GetIndexer().ByIndex(userNameIndex, userName)
	if err != nil {
		return UserRecord{}, false, fmt.Errorf("lookup by user name: %w", err)
	}

	for _, obj := range objects {
		user, err := decodeUser(obj)
		if err != nil {
			continue
		}
		record, ok := userRecordFromUser(user)
		if !ok || !record.Enabled {
			continue
		}
		return record, true, nil
	}

	return UserRecord{}, false, nil
}

func (c *UserCache) eventHandler() cache.ResourceEventHandler {
	markHealthy := func(_ any) {
		c.healthy.Store(true)
	}

	return cache.ResourceEventHandlerFuncs{
		AddFunc: markHealthy,
		UpdateFunc: func(oldObj, newObj any) {
			c.healthy.Store(true)
			oldUser, err := decodeUser(oldObj)
			if err != nil {
				return
			}
			newUser, err := decodeUser(newObj)
			if err != nil {
				return
			}
			if revokedOnUpdate(oldUser, newUser) {
				c.handleRevocation(newUser)
			}
		},
		DeleteFunc: func(obj any) {
			markHealthy(obj)
			user, err := decodeUser(obj)
			if err != nil {
				return
			}
			c.handleRevocation(user)
		},
	}
}

func (c *UserCache) handleRevocation(user *v1alpha1.User) {
	record, ok := userRecordFromUser(user)
	if !ok {
		return
	}

	c.mu.RLock()
	handler := c.onRevoke
	c.mu.RUnlock()

	if handler == nil {
		return
	}
	handler(record)
}

func (c *UserCache) indexers() cache.Indexers {
	return cache.Indexers{
		userNameIndex: c.indexUserNames,
	}
}

func (c *UserCache) indexUserNames(obj any) ([]string, error) {
	user, err := decodeUser(obj)
	if err != nil {
		return nil, nil
	}
	if user.Spec.UserName == "" {
		return nil, nil
	}
	return []string{user.Spec.UserName}, nil
}

func decodeUser(obj any) (*v1alpha1.User, error) {
	switch value := obj.(type) {
	case *v1alpha1.User:
		return value, nil
	case *unstructured.Unstructured:
		user := &v1alpha1.User{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			value.Object,
			user,
		); err != nil {
			return nil, err
		}
		return user, nil
	case cache.DeletedFinalStateUnknown:
		return decodeUser(value.Obj)
	default:
		return nil, fmt.Errorf("unexpected object type %T", obj)
	}
}

func userEnabled(user *v1alpha1.User) bool {
	if user == nil {
		return false
	}
	if user.Spec.Enabled == nil {
		return true
	}
	return *user.Spec.Enabled
}

func revokedOnUpdate(oldUser, newUser *v1alpha1.User) bool {
	if oldUser == nil || newUser == nil {
		return false
	}
	return userEnabled(oldUser) && !userEnabled(newUser)
}

func userRecordFromUser(user *v1alpha1.User) (UserRecord, bool) {
	if user == nil || user.Spec.UserName == "" {
		return UserRecord{}, false
	}

	enabled := userEnabled(user)
	ssoRequired := userSSORequired(user)
	subjects := userOIDCSubjects(user)
	groups := userOIDCGroups(user)

	return UserRecord{
		Name:            user.Name,
		UserName:        user.Spec.UserName,
		PublicKeys:      append([]string(nil), user.Spec.PublicKeys...),
		Enabled:         enabled,
		SSORequired:     ssoRequired,
		OIDCSubjects:    subjects,
		OIDCGroups:      groups,
		ResourceVersion: user.ResourceVersion,
	}, true
}

func userSSORequired(user *v1alpha1.User) bool {
	if user == nil || user.Spec.Auth == nil || user.Spec.Auth.SSORequired == nil {
		return false
	}
	return *user.Spec.Auth.SSORequired
}

func userOIDCSubjects(user *v1alpha1.User) []string {
	if user == nil || user.Spec.OIDC == nil {
		return nil
	}
	return append([]string(nil), user.Spec.OIDC.Subjects...)
}

func userOIDCGroups(user *v1alpha1.User) []string {
	if user == nil || user.Spec.OIDC == nil {
		return nil
	}
	return append([]string(nil), user.Spec.OIDC.Groups...)
}

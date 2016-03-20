package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
)

// KeyData contains a key along with its expiry time and KID.
type KeyData struct {
	KID    string `gorm:"primary_key"`
	Key    []byte
	Expiry time.Time
}

// NewKey generates a new key with the given expiry time.
func NewKey(expiry time.Time) (*KeyData, error) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(key)
	return &KeyData{
		KID:    base64.RawURLEncoding.EncodeToString(keyHash[:]),
		Key:    key,
		Expiry: expiry,
	}, nil
}

// KeyStore is a generic interface for generating tokens and accessing keys.
type KeyStore interface {
	NewToken(map[string]interface{}) (string, time.Time, error)
	GetLatest() (*KeyData, error)
	Get(kid string) (*KeyData, bool)
	Add(k *KeyData)
	Remove(kid string)
}

type keystore struct {
	sync.RWMutex
	cache          map[string]*KeyData
	db             *gorm.DB
	latest         string
	step, lifetime time.Duration
}

// NewKeystore creates a default SQL backed KeyStore that generates keys
// starting at `step` intervals with a given total `lifetime`.
func NewKeystore(db *gorm.DB, step, lifetime time.Duration) KeyStore {
	db.CreateTable(&KeyData{})
	return &keystore{
		cache:    make(map[string]*KeyData),
		db:       db,
		step:     step,
		lifetime: lifetime,
	}
}

func (ks *keystore) NewToken(claims map[string]interface{}) (t string, expiry time.Time, err error) {
	k, err := ks.GetLatest()
	if err != nil {
		return
	}

	expiry = k.Expiry

	token := jwt.New(jwt.SigningMethodHS256)
	if claims != nil {
		token.Claims = claims
	}
	token.Claims["vrs"] = "1"
	token.Claims["kid"] = k.KID
	token.Claims["exp"] = k.Expiry.Unix()

	t, err = token.SignedString(k.Key)
	return
}

func (ks *keystore) GetLatest() (*KeyData, error) {
	var err error
	k, ok := ks.Get(ks.latest)
	if !ok || k.Expiry.Before(time.Now().Truncate(ks.step).Add(ks.lifetime)) {
		k, err = NewKey(time.Now().Truncate(ks.step).Add(ks.lifetime))
		if err != nil {
			return nil, err
		}
		ks.Add(k)
	}

	return k, nil
}

func (ks *keystore) Get(kid string) (*KeyData, bool) {
	ks.RLock()
	k, ok := ks.cache[kid]
	ks.RUnlock()
	if !ok {
		k = &KeyData{KID: kid}
		ks.db.First(k)
		if k.Key != nil {
			ks.addCached(k)
			ok = true
		}
	}
	return k, ok
}

func (ks *keystore) addCached(k *KeyData) {
	ks.Lock()
	defer ks.Unlock()
	ks.cache[k.KID] = k
	if latestKey, ok := ks.cache[ks.latest]; !ok || k.Expiry.After(latestKey.Expiry) {
		ks.latest = k.KID
	}
}

func (ks *keystore) Add(k *KeyData) {
	ks.addCached(k)
	ks.db.Create(k)
}

func (ks *keystore) Remove(kid string) {
	ks.Lock()
	defer ks.Unlock()
	delete(ks.cache, kid)

	// Do we need to hold the lock here?
	ks.db.Delete(&KeyData{KID: kid})
}

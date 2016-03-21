package auth

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
)

// KeyData contains a key along with its expiry time and ID.
type KeyData struct {
	ID     uint `gorm:"primary_key"`
	Key    []byte
	Expiry time.Time
}

// NewKey generates a new key with the given expiry time.
func NewKey(expiry time.Time) (*KeyData, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &KeyData{
		Key:    key,
		Expiry: expiry,
	}, nil
}

// KeyStore is a generic interface for generating tokens and accessing keys.
type KeyStore interface {
	NewToken(map[string]interface{}) (string, time.Time, error)
	GetKey(token *jwt.Token) (interface{}, error)
	Get(id uint) (*KeyData, bool)
	Add(k *KeyData)
	Remove(id uint)
}

type keystore struct {
	sync.RWMutex
	cache          map[uint]*KeyData
	db             *gorm.DB
	lastID         uint
	step, lifetime time.Duration
}

// NewKeystore creates a default SQL backed KeyStore that generates keys
// starting at `step` intervals with a given total `lifetime`.
func NewKeystore(db *gorm.DB, step, lifetime time.Duration) KeyStore {
	db.CreateTable(&KeyData{})
	return &keystore{
		cache:    make(map[uint]*KeyData),
		db:       db,
		step:     step,
		lifetime: lifetime,
	}
}

func (ks *keystore) NewToken(claims map[string]interface{}) (t string, expiry time.Time, err error) {
	k, err := ks.getLatest()
	if err != nil {
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	if claims != nil {
		token.Claims = claims
	}
	token.Claims["vrs"] = "1"
	token.Claims["exp"] = k.Expiry.Unix()
	token.Claims["id"] = k.ID

	t, err = token.SignedString(k.Key)
	expiry = k.Expiry
	return
}

// GetKey returns the key in the KeyStore associated with a token's kid.
func (ks *keystore) GetKey(token *jwt.Token) (interface{}, error) {
	id, ok := token.Claims["kid"].(uint)
	if !ok {
		return nil, fmt.Errorf("invalid kid: %v", token.Claims["kid"])
	}

	k, ok := ks.Get(id)
	if !ok {
		return nil, fmt.Errorf("couldn't find id %d", id)
	}

	return k.Key, nil
}

func (ks *keystore) getLatest() (*KeyData, error) {
	var err error
	k, ok := ks.Get(ks.lastID)
	if !ok || k.Expiry.Before(time.Now().Truncate(ks.step).Add(ks.lifetime)) {
		k, err = NewKey(time.Now().Truncate(ks.step).Add(ks.lifetime))
		if err != nil {
			return nil, err
		}
		ks.Add(k)
	}

	return k, nil
}

func (ks *keystore) Get(id uint) (*KeyData, bool) {
	if id == 0 {
		id = ks.lastID
	}
	ks.RLock()
	k, ok := ks.cache[id]
	ks.RUnlock()
	if !ok {
		k = &KeyData{ID: id}
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
	ks.cache[k.ID] = k
	if lastIDKey, ok := ks.cache[ks.lastID]; !ok || k.Expiry.After(lastIDKey.Expiry) {
		ks.lastID = k.ID
	}
}

func (ks *keystore) Add(k *KeyData) {
	ks.db.Create(k)
	ks.addCached(k)
}

func (ks *keystore) Remove(id uint) {
	ks.Lock()
	defer ks.Unlock()
	delete(ks.cache, id)

	// Do we need to hold the lock here?
	ks.db.Delete(&KeyData{ID: id})
}

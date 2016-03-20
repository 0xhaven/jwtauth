package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type KeyStore struct {
	cache          map[string]*Key
	first, last    string
	step, lifetime time.Duration
	sync.RWMutex
}

func NewKeyStore(step, lifetime time.Duration) *KeyStore {
	return &KeyStore{
		cache:    make(map[string]*Key),
		step:     step,
		lifetime: lifetime,
	}
}

func (ks *KeyStore) NewToken() (*jwt.Token, *Key, error) {
	k, err := ks.GetLatest()
	if err != nil {
		return nil, nil, err
	}
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["version"] = "1"
	token.Claims["kid"] = k.kid
	token.Claims["exp"] = k.expiry.Unix()
	return token, k, nil
}

func (ks *KeyStore) GetLatest() (*Key, error) {
	var err error
	k, ok := ks.Get(ks.first)
	if !ok || k.expiry.Sub(time.Now()) > ks.step {
		k, err = NewKey(time.Now().Truncate(ks.step).Add(ks.lifetime))
		if err != nil {
			return nil, err
		}
		ks.Add(k)
	}

	return k, nil
}

func (ks *KeyStore) Get(kid string) (*Key, bool) {
	ks.RLock()
	defer ks.RUnlock()
	k, ok := ks.cache[kid]
	return k, ok
}

func (ks *KeyStore) Add(k *Key) {
	ks.Lock()
	defer ks.Unlock()
	ks.cache[k.kid] = k
	if firstKey, ok := ks.cache[ks.first]; !ok || firstKey.expiry.After(k.expiry) {
		k.next = ks.first
		ks.first = k.kid
	}
	if lastKey, ok := ks.cache[ks.last]; !ok || lastKey.expiry.Before(k.expiry) {
		ks.last = k.kid
		if lastKey != nil {
			lastKey.next = k.kid
		}
	}
}

func (ks *KeyStore) Remove(kid string) {
	ks.Lock()
	defer ks.Unlock()
	delete(ks.cache, kid)
}

type Key struct {
	key       []byte
	expiry    time.Time
	kid, next string
}

func NewKey(expiry time.Time) (*Key, error) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(key)
	return &Key{
		expiry: expiry,
		kid:    base64.RawURLEncoding.EncodeToString(keyHash[:]),
		key:    key,
	}, nil
}

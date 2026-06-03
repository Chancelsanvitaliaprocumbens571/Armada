package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var rdb *redis.Client

func initRedis(redisURL string) error {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("invalid redis URL: %w", err)
	}
	rdb = redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}
	log.Printf("[REDIS] connected to %s", opts.Addr)
	return nil
}

// UserCreds holds the parsed user data from Redis, plus targeting filters
// extracted from the username (e.g. "alice-country-US-session-xyz").
type UserCreds struct {
	UserID string
	Filter *ProxyFilter // targeting params parsed from username
}

// CheckCredentials looks up pbuy:creds:{baseUser} and verifies the password.
// The raw username may contain targeting parameters (see ParseProxyUser).
// Redis value format: userID:gb:quotaBytes:proxyPass
func CheckCredentials(ctx context.Context, username, password string) (*UserCreds, error) {
	f := ParseProxyUser(username)
	if f.BaseUser == "" {
		return nil, fmt.Errorf("empty username")
	}
	val, err := rdb.Get(ctx, "pbuy:creds:"+f.BaseUser).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("user not found: %q", f.BaseUser)
	}
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}
	parts := strings.SplitN(val, ":", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("malformed credentials entry for %q", f.BaseUser)
	}
	userID := parts[0]
	if userID == "" {
		return nil, fmt.Errorf("empty userID in credentials for %q", f.BaseUser)
	}
	if parts[3] != password {
		return nil, fmt.Errorf("wrong password for %q", f.BaseUser)
	}
	// Populate UserID into the filter so session keys are scoped per user
	f.UserID = userID
	return &UserCreds{UserID: userID, Filter: f}, nil
}

// quotaKey returns the Redis key for a user's quota.
// Panics if userID is empty to surface misconfiguration early.
func quotaKey(userID string) string {
	if userID == "" {
		panic("quota operation on empty userID")
	}
	return "pbuy:quota:" + userID
}

// GetQuota returns remaining bytes for the user.
func GetQuota(ctx context.Context, userID string) (int64, error) {
	val, err := rdb.Get(ctx, quotaKey(userID)).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

// ReserveQuota atomically pre-reserves n bytes from the user's quota.
// Returns the remaining quota after reservation. If the result is negative,
// quota is exhausted and the caller must release the reservation via
// RefundQuota and deny the connection.
func ReserveQuota(ctx context.Context, userID string, n int64) (int64, error) {
	return rdb.DecrBy(ctx, quotaKey(userID), n).Result()
}

// RefundQuota returns n bytes of unused reserved quota back to the user.
func RefundQuota(ctx context.Context, userID string, n int64) {
	if n <= 0 {
		return
	}
	if err := rdb.IncrBy(ctx, quotaKey(userID), n).Err(); err != nil {
		log.Printf("[REDIS] refund quota error for %s: %v", userID, err)
	}
}

// DeductQuota atomically decrements the quota by n bytes and returns the new value.
func DeductQuota(ctx context.Context, userID string, n int64) (int64, error) {
	if n == 0 {
		return 0, nil
	}
	return rdb.DecrBy(ctx, quotaKey(userID), n).Result()
}

package accounts

import (
	"fmt"
	"io"
	"strconv"
)

const shadowFile = "/etc/shadow"

type ShadowEntry struct {
	Name       string
	Hash       string
	LastChange *int
	MinDays    *int
	MaxDays    *int
	WarnDays   *int
	Inactive   *int
	Expire     *int
}

func optInt(s string) (*int, error) {
	if s == "" {
		return nil, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func parseShadowEntry(f []string) (ShadowEntry, error) {
	if len(f) < 9 {
		return ShadowEntry{}, fmt.Errorf("expected 9 fields, got %d", len(f))
	}

	lastChange, err := optInt(f[2])
	if err != nil {
		return ShadowEntry{}, fmt.Errorf("invalid LastChange: %w", err)
	}
	minDays, err := optInt(f[3])
	if err != nil {
		return ShadowEntry{}, fmt.Errorf("invalid MinDays: %w", err)
	}
	maxDays, err := optInt(f[4])
	if err != nil {
		return ShadowEntry{}, fmt.Errorf("invalid MaxDays: %w", err)
	}
	warnDays, err := optInt(f[5])
	if err != nil {
		return ShadowEntry{}, fmt.Errorf("invalid WarnDays: %w", err)
	}
	inactive, err := optInt(f[6])
	if err != nil {
		return ShadowEntry{}, fmt.Errorf("invalid Inactive: %w", err)
	}
	expire, err := optInt(f[7])
	if err != nil {
		return ShadowEntry{}, fmt.Errorf("invalid Expire: %w", err)
	}

	return ShadowEntry{
		Name:       f[0],
		Hash:       f[1],
		LastChange: lastChange,
		MinDays:    minDays,
		MaxDays:    maxDays,
		WarnDays:   warnDays,
		Inactive:   inactive,
		Expire:     expire,
	}, nil
}

func parseShadow(r io.Reader) ([]ShadowEntry, error) {
	return ParseLines(r, ":", SkipAny(SkipComments, SkipEmpty), parseShadowEntry)
}

func ReadShadow() ([]ShadowEntry, error) {
	return ReadLines(shadowFile, parseShadow)
}

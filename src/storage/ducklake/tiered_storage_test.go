// Copyright (C) 2026 Homer Server Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ducklake

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
)

// TestAttachVolume_CredentialChain verifies that an S3 volume with no
// static access key and no custom endpoint creates a secret with
// PROVIDER credential_chain instead of empty KEY_ID/SECRET.
func TestAttachVolume_CredentialChain(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("LOAD ducklake;"); err != nil {
		t.Fatalf("load ducklake: %v", err)
	}
	if _, err := db.Exec("LOAD sqlite;"); err != nil {
		t.Fatalf("load sqlite: %v", err)
	}
	// aws extension needed for credential_chain provider
	if _, err := db.Exec("INSTALL aws; LOAD aws;"); err != nil {
		t.Skipf("aws extension not available: %v", err)
	}

	tsm := &TieredStorageManager{db: db}

	vol := &Volume{
		Name:     "cold",
		Type:     VolumeTypeS3,
		Path:     "s3://test-bucket/data",
		LakeName: "homer_lake_cold",
		S3Region: "us-east-1",
		// S3AccessKey intentionally empty — should trigger credential_chain
	}

	catalogPath := t.TempDir() + "/test_catalog.sqlite"
	tsm.config.CatalogPath = catalogPath

	err = tsm.attachVolume(vol)
	if err != nil {
		t.Fatalf("attachVolume: %v", err)
	}

	// Verify the secret was created with credential_chain provider
	rows, err := db.Query("SELECT name, type, provider FROM duckdb_secrets()")
	if err != nil {
		t.Fatalf("query secrets: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var name, stype, provider string
		if err := rows.Scan(&name, &stype, &provider); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "s3_secret_cold" {
			found = true
			if stype != "s3" {
				t.Errorf("secret type = %q, want s3", stype)
			}
			if provider != "credential_chain" {
				t.Errorf("secret provider = %q, want credential_chain", provider)
			}
		}
	}
	if !found {
		t.Error("secret s3_secret_cold not found")
	}
}

// TestAttachVolume_StaticKeys verifies that an S3 volume with explicit
// access keys creates a secret with those keys (not credential_chain).
func TestAttachVolume_StaticKeys(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("LOAD ducklake;"); err != nil {
		t.Fatalf("load ducklake: %v", err)
	}
	if _, err := db.Exec("LOAD sqlite;"); err != nil {
		t.Fatalf("load sqlite: %v", err)
	}

	tsm := &TieredStorageManager{db: db}

	vol := &Volume{
		Name:        "cold",
		Type:        VolumeTypeS3,
		Path:        "s3://test-bucket/data",
		LakeName:    "homer_lake_cold",
		S3Region:    "us-east-1",
		S3AccessKey: "AKIAIOSFODNN7EXAMPLE",
		S3SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	catalogPath := t.TempDir() + "/test_catalog.sqlite"
	tsm.config.CatalogPath = catalogPath

	err = tsm.attachVolume(vol)
	if err != nil {
		t.Fatalf("attachVolume: %v", err)
	}

	rows, err := db.Query("SELECT name, type, provider FROM duckdb_secrets()")
	if err != nil {
		t.Fatalf("query secrets: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var name, stype, provider string
		if err := rows.Scan(&name, &stype, &provider); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "s3_secret_cold" {
			found = true
			if stype != "s3" {
				t.Errorf("secret type = %q, want s3", stype)
			}
			if provider != "config" {
				t.Errorf("secret provider = %q, want config (explicit keys)", provider)
			}
		}
	}
	if !found {
		t.Error("secret s3_secret_cold not found")
	}
}

// TestAttachVolume_CustomEndpoint verifies that an S3 volume with a
// custom endpoint (MinIO/R2) uses explicit keys even when access key
// is empty (preserving existing behaviour for S3-compatible stores).
func TestAttachVolume_CustomEndpoint(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("LOAD ducklake;"); err != nil {
		t.Fatalf("load ducklake: %v", err)
	}
	if _, err := db.Exec("LOAD sqlite;"); err != nil {
		t.Fatalf("load sqlite: %v", err)
	}

	tsm := &TieredStorageManager{db: db}

	vol := &Volume{
		Name:       "cold",
		Type:       VolumeTypeS3,
		Path:       "s3://test-bucket/data",
		LakeName:   "homer_lake_cold",
		S3Region:   "us-east-1",
		S3Endpoint: "http://minio.local:9000",
		S3UseSSL:   false,
		// S3AccessKey empty — but endpoint is set, so should NOT use credential_chain
	}

	catalogPath := t.TempDir() + "/test_catalog.sqlite"
	tsm.config.CatalogPath = catalogPath

	err = tsm.attachVolume(vol)
	if err != nil {
		t.Fatalf("attachVolume: %v", err)
	}

	rows, err := db.Query("SELECT name, type, provider FROM duckdb_secrets()")
	if err != nil {
		t.Fatalf("query secrets: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var name, stype, provider string
		if err := rows.Scan(&name, &stype, &provider); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "s3_secret_cold" {
			found = true
			if provider == "credential_chain" {
				t.Error("custom endpoint volume should not use credential_chain")
			}
		}
	}
	if !found {
		t.Error("secret s3_secret_cold not found")
	}
}

// TestBuildS3SecretSQL_Branches exercises the three-way switch in
// attachVolume's secret creation without needing a live DuckDB.
func TestBuildS3SecretSQL_Branches(t *testing.T) {
	cases := []struct {
		name       string
		accessKey  string
		endpoint   string
		region     string
		wantSubstr string
		denySubstr string
	}{
		{
			name:       "empty key + no endpoint → credential_chain",
			accessKey:  "",
			endpoint:   "",
			wantSubstr: "PROVIDER credential_chain",
			denySubstr: "KEY_ID",
		},
		{
			name:       "empty key + empty region → credential_chain defaults region",
			accessKey:  "",
			endpoint:   "",
			region:     "",
			wantSubstr: "REGION 'us-east-1'",
			denySubstr: "REGION ''",
		},
		{
			name:       "whitespace key + no endpoint → credential_chain",
			accessKey:  "   ",
			endpoint:   "",
			wantSubstr: "PROVIDER credential_chain",
			denySubstr: "KEY_ID",
		},
		{
			name:       "static key + no endpoint → explicit keys",
			accessKey:  "AKIA...",
			endpoint:   "",
			wantSubstr: "KEY_ID",
			denySubstr: "credential_chain",
		},
		{
			name:       "empty key + custom endpoint → explicit keys (MinIO path)",
			accessKey:  "",
			endpoint:   "minio.local:9000",
			wantSubstr: "KEY_ID",
			denySubstr: "credential_chain",
		},
		{
			name:       "static key + custom endpoint → explicit keys",
			accessKey:  "AKIA...",
			endpoint:   "minio.local:9000",
			wantSubstr: "KEY_ID",
			denySubstr: "credential_chain",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql := buildS3SecretSQL("test_secret", tc.accessKey, "secret", tc.region, tc.endpoint, true)
			if !strings.Contains(sql, tc.wantSubstr) {
				t.Errorf("SQL should contain %q:\n%s", tc.wantSubstr, sql)
			}
			if tc.denySubstr != "" && strings.Contains(sql, tc.denySubstr) {
				t.Errorf("SQL should not contain %q:\n%s", tc.denySubstr, sql)
			}
		})
	}
}

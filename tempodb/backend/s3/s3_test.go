package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/grafana/dskit/flagext"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/tempo/tempodb/backend"
)

const (
	getMethod          = "GET"
	putMethod          = "PUT"
	tagHeader          = "X-Amz-Tagging"
	storageClassHeader = "X-Amz-Storage-Class"

	defaultAccessKey = "AKIAIOSFODNN7EXAMPLE"
	defaultSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	user1AccessKey   = "AKIAI44QH8DHBEXAMPLE"
	user1SecretKey   = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
)

type ec2RoleCredRespBody struct {
	Expiration      time.Time `json:"Expiration"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Code            string    `json:"Code"`
	Message         string    `json:"Message"`
	LastUpdated     time.Time `json:"LastUpdated"`
	Type            string    `json:"Type"`
}

// TestFetchCreds verifies that fetchCreds() correctly handles individual
// credential sources. Each test only configures the specific source being
// validated.
func TestFetchCreds(t *testing.T) {
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	// Set up mock IAM endpoint once for all tests (for security and efficiency)
	metadataSrv := httptest.NewServer(metadataMockedHandler(t))
	t.Cleanup(metadataSrv.Close)

	tests := []struct {
		name     string
		access   string
		secret   string
		envs     map[string]string
		profile  string
		expected credentials.Value
	}{
		{
			name: "no-creds",
			// anonymous access is the last in the chain of fetchCreds,
			// so we need to set an invalid endpoint to prevent IAM access
			envs: map[string]string{
				"TEST_IAM_ENDPOINT": "http://invalid-endpoint-to-prevent-iam-access:9999",
			},
			expected: credentials.Value{
				SignerType: credentials.SignatureAnonymous,
			},
		},
		{
			name: "aws-env",
			envs: map[string]string{
				"AWS_ACCESS_KEY_ID":     defaultAccessKey,
				"AWS_SECRET_ACCESS_KEY": defaultSecretKey,
			},
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureV4,
			},
		},
		{
			name:   "aws-static",
			access: defaultAccessKey,
			secret: defaultSecretKey,
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureDefault,
			},
		},
		{
			name: "minio-env",
			envs: map[string]string{
				"MINIO_ACCESS_KEY": defaultAccessKey,
				"MINIO_SECRET_KEY": defaultSecretKey,
			},
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureV4,
			},
		},
		{
			name: "aws-config-no-profile",
			envs: map[string]string{
				"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(cwd, "testdata/aws-credentials"),
			},
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureV4,
			},
		},
		{
			name: "aws-config-with-profile",
			envs: map[string]string{
				"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(cwd, "testdata/aws-credentials"),
				"AWS_PROFILE":                 "user1",
			},
			expected: credentials.Value{
				AccessKeyID:     user1AccessKey,
				SecretAccessKey: user1SecretKey,
				SignerType:      credentials.SignatureV4,
			},
		},
		{
			name: "minio-config",
			envs: map[string]string{
				"MINIO_SHARED_CREDENTIALS_FILE": filepath.Join(cwd, "testdata/minio-config.json"),
				"MINIO_ALIAS":                   "s3",
			},
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureV4,
			},
		},
		{
			name: "aws-iam-irsa-mocked",
			envs: map[string]string{
				"AWS_WEB_IDENTITY_TOKEN_FILE": filepath.Join(cwd, "testdata/iam-token"),
				"AWS_ROLE_ARN":                "arn:aws:iam::123456789012:role/role-name",
				"AWS_ROLE_SESSION_NAME":       "tempo",
			},
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureV4,
			},
		},
		{
			name: "aws-iam-imds-mocked",
			envs: map[string]string{
				"AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/role-name",
			},
			expected: credentials.Value{
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				SignerType:      credentials.SignatureV4,
				Expiration:      timeNow().Add(time.Hour),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clear all credential-related environment variables for isolation
			// because some may exist in the environment
			credentialVars := []string{
				"AWS_ACCESS_KEY_ID",
				"AWS_SECRET_ACCESS_KEY",
				"AWS_SESSION_TOKEN",
				"AWS_PROFILE",
				"AWS_SHARED_CREDENTIALS_FILE",
				"AWS_CONFIG_FILE",
				"MINIO_ACCESS_KEY",
				"MINIO_SECRET_KEY",
				"MINIO_SHARED_CREDENTIALS_FILE",
				"MINIO_ALIAS",
				"AWS_WEB_IDENTITY_TOKEN_FILE",
				"AWS_ROLE_ARN",
				"AWS_ROLE_SESSION_NAME",
			}
			for _, envVar := range credentialVars {
				os.Unsetenv(envVar)
			}

			// Use shared mock IAM endpoint for security (prevents real IAM access if it exists)
			t.Setenv("TEST_IAM_ENDPOINT", metadataSrv.URL)

			// Set test-specific environment variables
			for name, value := range tc.envs {
				t.Setenv(name, value)
			}

			c := &Config{}
			if tc.access != "" {
				c.AccessKey = tc.access
				c.SecretKey = flagext.SecretWithValue(tc.secret)
			}

			creds, err := fetchCreds(c)
			assert.NoError(t, err)

			realCreds, err := creds.GetWithContext(nil)
			assert.NoError(t, err)

			assert.Equal(t, tc.expected, realCreds)
		})
	}
}

func TestHedge(t *testing.T) {
	tests := []struct {
		name                   string
		returnIn               time.Duration
		hedgeAt                time.Duration
		expectedHedgedRequests int32
	}{
		{
			name:                   "hedge disabled",
			expectedHedgedRequests: 1,
		},
		{
			name:                   "hedge enabled doesn't hit",
			hedgeAt:                time.Hour,
			expectedHedgedRequests: 1,
		},
		{
			name:                   "hedge enabled and hits",
			hedgeAt:                time.Millisecond,
			returnIn:               100 * time.Millisecond,
			expectedHedgedRequests: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			count := int32(0)
			server := fakeServer(t, tc.returnIn, &count)

			r, w, _, err := New(&Config{
				Region:            "blerg",
				AccessKey:         "test",
				SecretKey:         flagext.SecretWithValue("test"),
				Bucket:            "blerg",
				Insecure:          true,
				Endpoint:          server.URL[7:], // [7:] -> strip http://
				HedgeRequestsAt:   tc.hedgeAt,
				HedgeRequestsUpTo: 2,
			})
			require.NoError(t, err)

			ctx := context.Background()

			// the first call on each client initiates an extra http request
			// clearing that here
			_, _, _ = r.Read(ctx, "object", backend.KeyPath{"test"}, nil)
			time.Sleep(tc.returnIn)
			atomic.StoreInt32(&count, 0)

			// calls that should hedge
			_, _, _ = r.Read(ctx, "object", backend.KeyPath{"test"}, nil)
			time.Sleep(tc.returnIn)
			assert.Equal(t, tc.expectedHedgedRequests, atomic.LoadInt32(&count))
			atomic.StoreInt32(&count, 0)

			_ = r.ReadRange(ctx, "object", backend.KeyPath{"test"}, 10, []byte{}, nil)
			time.Sleep(tc.returnIn)
			assert.Equal(t, tc.expectedHedgedRequests, atomic.LoadInt32(&count))
			atomic.StoreInt32(&count, 0)

			// calls that should not hedge
			_, _ = r.List(ctx, backend.KeyPath{"test"})
			assert.Equal(t, int32(1), atomic.LoadInt32(&count))
			atomic.StoreInt32(&count, 0)

			_ = w.Write(ctx, "object", backend.KeyPath{"test"}, bytes.NewReader([]byte{}), 0, nil)
			assert.Equal(t, int32(1), atomic.LoadInt32(&count))
			atomic.StoreInt32(&count, 0)
		})
	}
}

func TestNilConfig(t *testing.T) {
	_, _, _, err := New(nil)
	require.Error(t, err)

	_, _, _, err = NewNoConfirm(nil)
	require.Error(t, err)
}

func fakeServer(t *testing.T, returnIn time.Duration, counter *int32) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(returnIn)

		atomic.AddInt32(counter, 1)
		// return fake list response b/c it's the only call that has to succeed
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
		<ListBucketResult>
		</ListBucketResult>`))
	}))
	t.Cleanup(server.Close)

	return server
}

func TestReadError(t *testing.T) {
	errA := minio.ErrorResponse{
		Code: s3.ErrCodeNoSuchKey,
	}
	errB := readError(errA)
	assert.Equal(t, backend.ErrDoesNotExist, errB)

	wups := fmt.Errorf("wups")
	errB = readError(wups)
	assert.Equal(t, wups, errB)
}

func fakeServerWithHeader(t *testing.T, obj *url.Values, testedHeaderName string) *httptest.Server {
	require.NotNil(t, obj)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch method := r.Method; method {
		case putMethod:
			// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
			switch testedHeaderValue := r.Header.Get(testedHeaderName); testedHeaderValue {
			case "":
			default:

				value, err := url.ParseQuery(testedHeaderValue)
				require.NoError(t, err)
				*obj = value
			}
		case getMethod:
			// return fake list response b/c it's the only call that has to succeed
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
		<ListBucketResult>
		</ListBucketResult>`))
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func TestObjectBlockTags(t *testing.T) {
	tests := []struct {
		name string
		tags map[string]string
		// expectedObject raw.Object
	}{
		{
			"env", map[string]string{"env": "prod", "app": "thing"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// rawObject := raw.Object{}
			var obj url.Values

			server := fakeServerWithHeader(t, &obj, tagHeader)
			_, w, _, err := New(&Config{
				Region:    "blerg",
				AccessKey: "test",
				SecretKey: flagext.SecretWithValue("test"),
				Bucket:    "blerg",
				Insecure:  true,
				Endpoint:  server.URL[7:], // [7:] -> strip http://
				Tags:      tc.tags,
			})
			require.NoError(t, err)

			ctx := context.Background()
			_ = w.Write(ctx, "object", backend.KeyPath{"test"}, bytes.NewReader([]byte{}), 0, nil)

			for k, v := range tc.tags {
				vv := obj.Get(k)
				require.NotEmpty(t, vv)
				require.Equal(t, v, vv)
			}
		})
	}
}

func TestObjectWithPrefix(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		objectName  string
		keyPath     backend.KeyPath
		httpHandler func(t *testing.T) http.HandlerFunc
	}{
		{
			name:       "with prefix",
			prefix:     "test_storage",
			objectName: "object",
			keyPath:    backend.KeyPath{"test"},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method == getMethod {
						assert.Equal(t, r.URL.Query().Get("prefix"), "test_storage")

						_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
						<ListBucketResult>
						</ListBucketResult>`))
						return
					}

					assert.Equal(t, "/blerg/test_storage/test/object", r.URL.String())
				}
			},
		},
		{
			name:       "without prefix",
			prefix:     "",
			objectName: "object",
			keyPath:    backend.KeyPath{"test"},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method == getMethod {
						assert.Equal(t, r.URL.Query().Get("prefix"), "")

						_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
						<ListBucketResult>
						</ListBucketResult>`))
						return
					}

					assert.Equal(t, "/blerg/test/object", r.URL.String())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := testServer(t, tc.httpHandler(t))
			_, w, _, err := New(&Config{
				Region:    "blerg",
				AccessKey: "test",
				SecretKey: flagext.SecretWithValue("test"),
				Bucket:    "blerg",
				Prefix:    tc.prefix,
				Insecure:  true,
				Endpoint:  server.URL[7:],
			})
			require.NoError(t, err)

			ctx := context.Background()
			err = w.Write(ctx, tc.objectName, tc.keyPath, bytes.NewReader([]byte{}), 0, nil)
			assert.NoError(t, err)
		})
	}
}

func TestListBlocksWithPrefix(t *testing.T) {
	tests := []struct {
		name              string
		prefix            string
		tenant            string
		liveBlockIDs      []uuid.UUID
		compactedBlockIDs []uuid.UUID
		httpHandler       func(t *testing.T) http.HandlerFunc
	}{
		{
			name:              "with prefix",
			prefix:            "a/b/c/",
			tenant:            "single-tenant",
			liveBlockIDs:      []uuid.UUID{uuid.MustParse("00000000-0000-0000-0000-000000000000")},
			compactedBlockIDs: []uuid.UUID{uuid.MustParse("00000000-0000-0000-0000-000000000001")},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method == getMethod {
						assert.Equal(t, "a/b/c/single-tenant/", r.URL.Query().Get("prefix"))

						_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
						<ListBucketResult>
							<Name>blerg</Name>
							<Prefix>a/b/c</Prefix>
							<ContinuationToken></ContinuationToken>
							<KeyCount>2</KeyCount>
							<MaxKeys>100</MaxKeys>
							<EncodingType>url</EncodingType>
							<IsTruncated>false</IsTruncated>
							<Contents>
								<Key>a/b/c/single-tenant/00000000-0000-0000-0000-000000000000/meta.json</Key>
								<LastModified>2024-03-01T00:00:00.000Z</LastModified>
								<ETag>&quot;d42a22ddd183f61924c661b1c026c1ef&quot;</ETag>
								<Size>398</Size>
								<StorageClass>STANDARD</StorageClass>
							</Contents>
							
							<Contents>
								<Key>a/b/c/single-tenant/00000000-0000-0000-0000-000000000001/meta.compacted.json</Key>
								<LastModified>2024-03-01T00:00:00.000Z</LastModified>
								<ETag>&quot;d42a22ddd183f61924c661b1c026c1ef&quot;</ETag>
								<Size>398</Size>
								<StorageClass>STANDARD</StorageClass>
							</Contents>
						</ListBucketResult>`))
						return
					}
				}
			},
		},
		{
			name:              "without prefix",
			prefix:            "",
			liveBlockIDs:      []uuid.UUID{uuid.MustParse("00000000-0000-0000-0000-000000000000")},
			compactedBlockIDs: []uuid.UUID{uuid.MustParse("00000000-0000-0000-0000-000000000001")},
			tenant:            "single-tenant",
			httpHandler: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method == getMethod {
						assert.Equal(t, "single-tenant/", r.URL.Query().Get("prefix"))

						_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
						<ListBucketResult>
							<Name>blerg</Name>
							<Prefix></Prefix>
							<ContinuationToken></ContinuationToken>
							<KeyCount>2</KeyCount>
							<MaxKeys>100</MaxKeys>
							<EncodingType>url</EncodingType>
							<IsTruncated>false</IsTruncated>
							<Contents>
								<Key>single-tenant/00000000-0000-0000-0000-000000000000/meta.json</Key>
								<LastModified>2024-03-01T00:00:00.000Z</LastModified>
								<ETag>&quot;d42a22ddd183f61924c661b1c026c1ef&quot;</ETag>
								<Size>398</Size>
								<StorageClass>STANDARD</StorageClass>
							</Contents>
							
							<Contents>
								<Key>single-tenant/00000000-0000-0000-0000-000000000001/meta.compacted.json</Key>
								<LastModified>2024-03-01T00:00:00.000Z</LastModified>
								<ETag>&quot;d42a22ddd183f61924c661b1c026c1ef&quot;</ETag>
								<Size>398</Size>
								<StorageClass>STANDARD</StorageClass>
							</Contents>
						</ListBucketResult>`))
						return
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := testServer(t, tc.httpHandler(t))
			r, _, _, err := NewNoConfirm(&Config{
				Region:                "blerg",
				AccessKey:             "test",
				SecretKey:             flagext.SecretWithValue("test"),
				Bucket:                "blerg",
				Prefix:                tc.prefix,
				Insecure:              true,
				Endpoint:              server.URL[7:],
				ListBlocksConcurrency: 1,
			})
			require.NoError(t, err)

			ctx := context.Background()
			blockIDs, compactedBlockIDs, err := r.ListBlocks(ctx, tc.tenant)
			assert.NoError(t, err)

			assert.ElementsMatchf(t, tc.liveBlockIDs, blockIDs, "Block IDs did not match")
			assert.ElementsMatchf(t, tc.compactedBlockIDs, compactedBlockIDs, "Compacted block IDs did not match")
		})
	}
}

func TestListObjectsVersion(t *testing.T) {
	const (
		tenant   = "single-tenant"
		liveID   = "00000000-0000-0000-0000-0000000000aa"
		liveKey  = tenant + "/" + liveID + "/meta.json"
		compID   = "00000000-0000-0000-0000-0000000000bb"
		compKey  = tenant + "/" + compID + "/meta.compacted.json"
		live2ID  = "00000000-0000-0000-0000-0000000000cc"
		live2Key = tenant + "/" + live2ID + "/meta.json"
	)

	v1Page := func(truncated bool, nextMarker string, keys ...string) string {
		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>blerg</Name>`)
		if truncated {
			sb.WriteString(`<IsTruncated>true</IsTruncated>`)
		} else {
			sb.WriteString(`<IsTruncated>false</IsTruncated>`)
		}
		sb.WriteString(`<NextMarker>` + nextMarker + `</NextMarker>`)
		for _, k := range keys {
			sb.WriteString(`<Contents><Key>` + k + `</Key><LastModified>2024-03-01T00:00:00.000Z</LastModified><ETag>&quot;abc&quot;</ETag><Size>398</Size><StorageClass>STANDARD</StorageClass></Contents>`)
		}
		sb.WriteString(`</ListBucketResult>`)
		return sb.String()
	}

	v2Page := func(keys ...string) string {
		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>blerg</Name><IsTruncated>false</IsTruncated>`)
		for _, k := range keys {
			sb.WriteString(`<Contents><Key>` + k + `</Key><LastModified>2024-03-01T00:00:00.000Z</LastModified><ETag>&quot;abc&quot;</ETag><Size>398</Size><StorageClass>STANDARD</StorageClass></Contents>`)
		}
		sb.WriteString(`</ListBucketResult>`)
		return sb.String()
	}

	tests := []struct {
		name               string
		listObjectsVersion string
		liveBlockIDs       []uuid.UUID
		compactedBlockIDs  []uuid.UUID
		httpHandler        func(t *testing.T) http.HandlerFunc
	}{
		{
			// (a) default → V2 on the wire
			name:               "default uses v2",
			listObjectsVersion: "",
			liveBlockIDs:       []uuid.UUID{uuid.MustParse(liveID)},
			compactedBlockIDs:  []uuid.UUID{uuid.MustParse(compID)},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method != getMethod {
						return
					}
					assert.Equal(t, "2", r.URL.Query().Get("list-type"), "default must use ListObjectsV2 on the wire")
					_, _ = w.Write([]byte(v2Page(liveKey, compKey)))
				}
			},
		},
		{
			// (b) v1 single page → no list-type
			name:               "v1 single page",
			listObjectsVersion: ListObjectsVersionV1,
			liveBlockIDs:       []uuid.UUID{uuid.MustParse(liveID)},
			compactedBlockIDs:  []uuid.UUID{uuid.MustParse(compID)},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method != getMethod {
						return
					}
					assert.Equal(t, "", r.URL.Query().Get("list-type"), "v1 must not send list-type")
					_, _ = w.Write([]byte(v1Page(false, "", liveKey, compKey)))
				}
			},
		},
		{
			// (c) v1 truncated two-page → page 2 carries the expected marker
			name:               "v1 truncated two pages with NextMarker",
			listObjectsVersion: ListObjectsVersionV1,
			liveBlockIDs:       []uuid.UUID{uuid.MustParse(liveID), uuid.MustParse(live2ID)},
			compactedBlockIDs:  []uuid.UUID{},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				var calls int
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method != getMethod {
						return
					}
					assert.Equal(t, "", r.URL.Query().Get("list-type"), "v1 must not send list-type")
					calls++
					if calls == 1 {
						// page 1: truncated, advertise NextMarker = liveKey
						_, _ = w.Write([]byte(v1Page(true, liveKey, liveKey)))
						return
					}
					// page 2: must carry the marker advertised by page 1
					assert.Equal(t, liveKey, r.URL.Query().Get("marker"), "page 2 must use NextMarker from page 1")
					_, _ = w.Write([]byte(v1Page(false, "", live2Key)))
				}
			},
		},
		{
			// (d) v1 truncated with EMPTY NextMarker → terminates via last key
			name:               "v1 truncated empty NextMarker terminates",
			listObjectsVersion: ListObjectsVersionV1,
			liveBlockIDs:       []uuid.UUID{uuid.MustParse(liveID)},
			compactedBlockIDs:  []uuid.UUID{uuid.MustParse(compID)},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				var calls int
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method != getMethod {
						return
					}
					assert.Equal(t, "", r.URL.Query().Get("list-type"), "v1 must not send list-type")
					calls++
					if calls == 1 {
						// page 1: truncated, EMPTY NextMarker, single Contents (liveKey)
						_, _ = w.Write([]byte(v1Page(true, "", liveKey)))
						return
					}
					// page 2: marker must fall back to the last key of page 1
					assert.Equal(t, liveKey, r.URL.Query().Get("marker"), "page 2 must fall back to last key when NextMarker empty")
					_, _ = w.Write([]byte(v1Page(false, "", compKey)))
				}
			},
		},
		{
			// (e) v1 truncated with empty NextMarker AND empty page → must terminate, not spin
			name:               "v1 truncated empty page terminates",
			listObjectsVersion: ListObjectsVersionV1,
			liveBlockIDs:       []uuid.UUID{},
			compactedBlockIDs:  []uuid.UUID{},
			httpHandler: func(t *testing.T) http.HandlerFunc {
				var calls int
				return func(w http.ResponseWriter, r *http.Request) {
					if r.Method != getMethod {
						return
					}
					calls++
					if calls > 1 {
						// A correct implementation cannot advance the marker on an empty,
						// NextMarker-less truncated page, so it must stop after page 1.
						t.Errorf("must not re-request after a non-advancing truncated page (call %d)", calls)
						_, _ = w.Write([]byte(v1Page(false, "")))
						return
					}
					// page 1: truncated, empty NextMarker, no Contents
					_, _ = w.Write([]byte(v1Page(true, "")))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := testServer(t, tc.httpHandler(t))
			r, _, _, err := NewNoConfirm(&Config{
				Region:                "blerg",
				AccessKey:             "test",
				SecretKey:             flagext.SecretWithValue("test"),
				Bucket:                "blerg",
				Insecure:              true,
				Endpoint:              server.URL[7:],
				ListBlocksConcurrency: 1,
				ListObjectsVersion:    tc.listObjectsVersion,
			})
			require.NoError(t, err)

			ctx := context.Background()
			blockIDs, compactedBlockIDs, err := r.ListBlocks(ctx, tenant)
			assert.NoError(t, err)

			assert.ElementsMatchf(t, tc.liveBlockIDs, blockIDs, "Block IDs did not match")
			assert.ElementsMatchf(t, tc.compactedBlockIDs, compactedBlockIDs, "Compacted block IDs did not match")
		})
	}
}

func TestObjectStorageClass(t *testing.T) {
	tests := []struct {
		name         string
		StorageClass string
		// expectedObject raw.Object
	}{
		{
			"Standard", "STANDARD",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// rawObject := raw.Object{}
			var obj url.Values

			server := fakeServerWithHeader(t, &obj, storageClassHeader)
			_, w, _, err := New(&Config{
				Region:       "blerg",
				AccessKey:    "test",
				SecretKey:    flagext.SecretWithValue("test"),
				Bucket:       "blerg",
				Insecure:     true,
				Endpoint:     server.URL[7:], // [7:] -> strip http://
				StorageClass: tc.StorageClass,
			})
			require.NoError(t, err)

			ctx := context.Background()
			_ = w.Write(ctx, "object", backend.KeyPath{"test"}, bytes.NewReader([]byte{}), 0, nil)
			require.Equal(t, obj.Has(tc.StorageClass), true)
		})
	}
}

func testServer(t *testing.T, httpHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	assert.NotNil(t, httpHandler)
	server := httptest.NewServer(httpHandler)
	t.Cleanup(server.Close)
	return server
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func metadataMockedHandler(t *testing.T) http.HandlerFunc {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/" {
			err := r.ParseForm()
			require.NoError(t, err)

			if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" {
				w.WriteHeader(400)
			}

			token, err := os.ReadFile(filepath.Join(cwd, "testdata/iam-token"))
			require.NoError(t, err)
			if r.Form.Get("WebIdentityToken") != string(token) {
				w.WriteHeader(400)
			}

			type xmlCreds struct {
				AccessKey    string    `xml:"AccessKeyId" json:"accessKey,omitempty"`
				SecretKey    string    `xml:"SecretAccessKey" json:"secretKey,omitempty"`
				Expiration   time.Time `xml:"Expiration" json:"expiration,omitempty"`
				SessionToken string    `xml:"SessionToken" json:"sessionToken,omitempty"`
			}

			assumeResponse := credentials.AssumeRoleWithWebIdentityResponse{
				Result: credentials.WebIdentityResult{
					Credentials: xmlCreds{
						AccessKey: defaultAccessKey,
						SecretKey: defaultSecretKey,
					},
				},
			}

			err1 := xml.NewEncoder(w).Encode(assumeResponse)
			require.NoError(t, err1)
		} else if r.URL.String() == "/latest/api/token" {
			// Check for X-aws-ec2-metadata-token-ttl-seconds request header
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				w.WriteHeader(400)
			}

			// Check X-aws-ec2-metadata-token-ttl-seconds is an integer
			secondsInt, err := strconv.Atoi(r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
			if err != nil {
				w.WriteHeader(400)
			}

			// Generate a token, 40 character string, base64 encoded
			token := base64.StdEncoding.EncodeToString([]byte(RandStringBytesMaskImprSrc(40)))

			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", strconv.Itoa(secondsInt))
			if _, err := w.Write([]byte(token)); err != nil {
				require.NoError(t, err)
			}
		} else if r.URL.String() == "/latest/meta-data/iam/security-credentials/" {
			if _, err := w.Write([]byte("role-name\n")); err != nil {
				require.NoError(t, err)
			}
		} else if r.URL.String() == "/latest/meta-data/iam/security-credentials/role-name" {
			creds := ec2RoleCredRespBody{
				LastUpdated:     timeNow(),
				Expiration:      timeNow().Add(1 * time.Hour),
				AccessKeyID:     defaultAccessKey,
				SecretAccessKey: defaultSecretKey,
				Type:            "AWS-HMAC",
				Code:            "Success",
			}

			err := json.NewEncoder(w).Encode(creds)
			require.NoError(t, err)
		}
	}
}

func timeNow() time.Time { return time.Date(2024, 5, 12, 16, 21, 24, 42, time.UTC) }

func TestDisableMultipartUpload(t *testing.T) {
	const tenant = "single-tenant"

	type capture struct {
		sawUploads atomic.Bool
		putCount   atomic.Int32
		putBody    atomic.Value // string
	}

	// handler that drives both the multipart flow and a single PutObject, recording which
	// path the backend took and the body of any single PUT.
	handler := func(c *capture) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			switch {
			case q.Has("uploads"): // CreateMultipartUpload
				c.sawUploads.Store(true)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>blerg</Bucket><Key>k</Key><UploadId>test-upload-id</UploadId></InitiateMultipartUploadResult>`))
			case q.Get("uploadId") != "" && r.Method == http.MethodPut: // UploadPart
				c.sawUploads.Store(true)
				w.Header().Set("ETag", `"abc"`)
				w.WriteHeader(http.StatusOK)
			case q.Get("uploadId") != "" && r.Method == http.MethodPost: // CompleteMultipartUpload
				c.sawUploads.Store(true)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Bucket>blerg</Bucket><Key>k</Key><ETag>"abc"</ETag></CompleteMultipartUploadResult>`))
			case r.Method == http.MethodPut: // single PutObject
				c.putCount.Add(1)
				body, _ := io.ReadAll(r.Body)
				c.putBody.Store(string(body))
				w.Header().Set("ETag", `"abc"`)
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}
	}

	writeObject := func(t *testing.T, disable bool) *capture {
		t.Helper()
		c := &capture{}
		server := testServer(t, handler(c))
		_, w, _, err := NewNoConfirm(&Config{
			Region:                 "blerg",
			AccessKey:              "test",
			SecretKey:              flagext.SecretWithValue("test"),
			Bucket:                 "blerg",
			Insecure:               true,
			Endpoint:               server.URL[7:],
			DisableMultipartUpload: disable,
		})
		require.NoError(t, err)
		ctx := context.Background()
		tracker, err := w.Append(ctx, "data", backend.KeyPath{tenant}, nil, []byte("hello "))
		require.NoError(t, err)
		tracker, err = w.Append(ctx, "data", backend.KeyPath{tenant}, tracker, []byte("world"))
		require.NoError(t, err)
		require.NoError(t, w.CloseAppend(ctx, tracker))
		return c
	}

	t.Run("disabled writes a single PutObject with the full body", func(t *testing.T) {
		c := writeObject(t, true)
		require.False(t, c.sawUploads.Load(), "must not initiate a multipart upload when disable_multipart_upload is set")
		require.Equal(t, int32(1), c.putCount.Load(), "object must be written with a single PutObject")
		body, _ := c.putBody.Load().(string)
		require.Contains(t, body, "hello world", "the single PutObject must carry the full buffered object in append order")
	})

	t.Run("default still uses multipart upload", func(t *testing.T) {
		c := writeObject(t, false)
		require.True(t, c.sawUploads.Load(), "default behavior must use a multipart upload")
		require.Zero(t, c.putCount.Load(), "default must not take the single-PutObject path")
	})
}

// Write() is the path the ingester uses to flush a finished block; unlike Append it hands
// minio-go a reader and a known size, so it needs its own guard. Without one, minio-go
// switches to a multipart upload above its default 16 MiB part size and stores that do not
// implement the multipart API reject the object.
func TestDisableMultipartUploadWrite(t *testing.T) {
	const tenant = "single-tenant"

	// Larger than minio-go's default 16 MiB part size, which is the threshold that decides
	// between a single PutObject and a multipart upload when part_size is not configured.
	body := bytes.Repeat([]byte("a"), 17*1024*1024)

	type capture struct {
		sawUploads atomic.Bool
		putCount   atomic.Int32
		putBytes   atomic.Int64
		putDecoded atomic.Int64
	}

	handler := func(c *capture) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			switch {
			case q.Has("uploads"): // CreateMultipartUpload
				c.sawUploads.Store(true)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>blerg</Bucket><Key>k</Key><UploadId>test-upload-id</UploadId></InitiateMultipartUploadResult>`))
			case q.Get("uploadId") != "" && r.Method == http.MethodPut: // UploadPart
				c.sawUploads.Store(true)
				w.Header().Set("ETag", `"abc"`)
				w.WriteHeader(http.StatusOK)
			case q.Get("uploadId") != "" && r.Method == http.MethodPost: // CompleteMultipartUpload
				c.sawUploads.Store(true)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Bucket>blerg</Bucket><Key>k</Key><ETag>"abc"</ETag></CompleteMultipartUploadResult>`))
			case r.Method == http.MethodPut: // single PutObject
				c.putCount.Add(1)
				// The body is framed with the streaming signature, so the bytes on the wire
				// exceed the payload; the decoded length header carries the real object size.
				if decoded, err := strconv.ParseInt(r.Header.Get("x-amz-decoded-content-length"), 10, 64); err == nil {
					c.putDecoded.Store(decoded)
				}
				n, _ := io.Copy(io.Discard, r.Body)
				c.putBytes.Store(n)
				w.Header().Set("ETag", `"abc"`)
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}
	}

	newWriter := func(t *testing.T, c *capture, disable bool) backend.RawWriter {
		t.Helper()
		server := testServer(t, handler(c))
		_, w, _, err := NewNoConfirm(&Config{
			Region:                 "blerg",
			AccessKey:              "test",
			SecretKey:              flagext.SecretWithValue("test"),
			Bucket:                 "blerg",
			Insecure:               true,
			Endpoint:               server.URL[7:],
			DisableMultipartUpload: disable,
		})
		require.NoError(t, err)
		return w
	}

	t.Run("disabled writes an over-part-size object with a single PutObject", func(t *testing.T) {
		c := &capture{}
		w := newWriter(t, c, true)
		require.NoError(t, w.Write(context.Background(), "data", backend.KeyPath{tenant}, bytes.NewReader(body), int64(len(body)), nil))
		require.False(t, c.sawUploads.Load(), "must not initiate a multipart upload when disable_multipart_upload is set")
		require.Equal(t, int32(1), c.putCount.Load(), "object must be written with a single PutObject")
		require.Equal(t, int64(len(body)), c.putDecoded.Load(), "the single PutObject must carry the whole object")
		require.GreaterOrEqual(t, c.putBytes.Load(), int64(len(body)), "the request body must hold at least the whole object")
	})

	t.Run("default still uses multipart upload", func(t *testing.T) {
		c := &capture{}
		w := newWriter(t, c, false)
		require.NoError(t, w.Write(context.Background(), "data", backend.KeyPath{tenant}, bytes.NewReader(body), int64(len(body)), nil))
		require.True(t, c.sawUploads.Load(), "default behavior must use a multipart upload above the part size")
	})

	t.Run("disabled rejects an unknown length instead of failing inside minio", func(t *testing.T) {
		c := &capture{}
		w := newWriter(t, c, true)
		err := w.Write(context.Background(), "data", backend.KeyPath{tenant}, bytes.NewReader(body), -1, nil)
		require.ErrorContains(t, err, "requires a known object size")
		require.Zero(t, c.putCount.Load())
	})

	t.Run("disabled rejects an object above the 5 GiB single-PutObject limit", func(t *testing.T) {
		c := &capture{}
		w := newWriter(t, c, true)
		err := w.Write(context.Background(), "data", backend.KeyPath{tenant}, bytes.NewReader(nil), maxSinglePutObjectSize+1, nil)
		require.ErrorContains(t, err, "S3 limits to 5 GiB")
		require.Zero(t, c.putCount.Load())
	})
}

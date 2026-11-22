package main

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	_ "modernc.org/sqlite"
	"gopkg.in/yaml.v3"
)

// sanitize turns a vunnel record identifier into a safe relative file path.
// Identifiers already use "/" to group related records (Alpine's
// "edge/CVE-...", NVD's "2026/CVE-..."), which makes a fine directory
// structure as-is; only ":" (seen in KEV's "kev:CVE-...") needs replacing,
// since it's awkward on some filesystems.
func sanitize(id string) string {
	return strings.ReplaceAll(id, ":", "-")
}

// emit writes the fast-import filemodify command for one vunnel record,
// re-encoding its JSON as YAML for better diffs. Unlike trivy-db, vunnel's
// records are already plain, self-describing JSON (each carries its own
// "schema" URL) so no decoding/enum-resolving step is needed here.
func emit(provider string, id string, record []byte) error {
	var parsed any
	if err := json.Unmarshal(record, &parsed); err != nil {
		return fmt.Errorf("json.Unmarshal failed for %s: %w", id, err)
	}
	pretty, err := yaml.Marshal(parsed)
	if err != nil {
		return fmt.Errorf("yaml.Marshal failed for %s: %w", id, err)
	}
	name := path.Join("providers", provider, sanitize(id)) + ".yaml"
	fmt.Printf("M 100644 inline %s\n", name)
	fmt.Printf("data %d\n%s\n", len(pretty), string(pretty))
	return nil
}

// metadata mirrors the subset of vunnel's per-provider metadata.json this
// tool cares about: when the cache was captured, for the commit timestamp.
type metadata struct {
	Provider   string    `json:"provider"`
	DataSource string    `json:"dataSource,omitempty"`
	URLs       []string  `json:"urls,omitempty"`
	Listing    *struct{} `json:"listing,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
}

func export(ctx context.Context, provider string, ref name.Reference) error {
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("remote.Image failed: %w", err)
	}
	dgst, err := img.Digest()
	if err != nil {
		return fmt.Errorf("(v1.Image).Digest failed: %w", err)
	}
	dgstRef := ref.Context().Digest(dgst.String())

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("(v1.Image).Layers failed: %w", err)
	} else if len(layers) != 1 {
		return fmt.Errorf("(v1.Image).Layers unexpected length: %d", len(layers))
	}

	rc, err := layers[0].Uncompressed()
	if err != nil {
		return fmt.Errorf("(v1.Layer).Uncompressed failed: %w", err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			log.Printf("(io.ReadCloser).Close failed: %v", err)
		}
	}()

	// Will contain the extracted 'results.db' file. Everything else in the
	// tarball (notably provider/input/*, which can run into the gigabytes)
	// is streamed past and discarded without ever touching disk.
	dbFile, err := os.CreateTemp("", "grype-db-*.db")
	if err != nil {
		return fmt.Errorf("os.CreateTemp failed: %w", err)
	}
	defer func() {
		if err := os.Remove(dbFile.Name()); err != nil {
			log.Printf("os.Remove failed: %v", err)
		}
	}()

	var meta metadata
	var sawResults bool

	resultsPath := path.Join(provider, "results", "results.db")
	metadataPath := path.Join(provider, "metadata.json")

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("(tar.Reader).Next failed: %w", err)
		}
		switch hdr.Name {
		case resultsPath:
			if _, err := io.Copy(dbFile, tr); err != nil {
				return fmt.Errorf("io.Copy failed: %w", err)
			}
			sawResults = true
		case metadataPath:
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("io.ReadAll failed: %w", err)
			}
			if err := json.Unmarshal(b, &meta); err != nil {
				return fmt.Errorf("json.Unmarshal of metadata.json failed: %w", err)
			}
		default:
			// Deliberately ignored: provider/input/* (raw upstream mirror,
			// can be multi-GB), provider/checksums, provider/results/observed-fix-dates.db.
		}
	}
	if !sawResults {
		return fmt.Errorf("tarball did not contain %s", resultsPath)
	}
	if err := dbFile.Close(); err != nil {
		return fmt.Errorf("(*os.File).Close failed: %w", err)
	}

	db, err := sql.Open("sqlite", dbFile.Name())
	if err != nil {
		return fmt.Errorf("sql.Open failed: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("(*sql.DB).Close failed: %v", err)
		}
	}()

	rows, err := db.QueryContext(ctx, "SELECT id, record FROM results ORDER BY id")
	if err != nil {
		return fmt.Errorf("(*sql.DB).QueryContext failed: %w", err)
	}
	defer rows.Close()

	// Replace refs/raw/grype/<provider>/<tag> with the exported contents
	refName := "refs/raw/grype/" + provider + "/" + ref.Identifier()
	fmt.Printf("reset %s\n", refName)
	fmt.Printf("commit %s\n", refName)

	committerTime := meta.Timestamp
	if committerTime.IsZero() {
		committerTime = time.Now().UTC()
	}
	fmt.Printf("committer grype-db-changelog <41898282+github-actions[bot]@users.noreply.github.com> %d +0000\n", committerTime.Unix())

	message := fmt.Sprintf("%s %s: %s", provider, ref.Identifier(), dgstRef.String())
	fmt.Printf("data %d\n%s\n", len(message), message)

	fmt.Printf("deleteall\n")

	for rows.Next() {
		var id string
		var record []byte
		if err := rows.Scan(&id, &record); err != nil {
			return fmt.Errorf("(*sql.Rows).Scan failed: %w", err)
		}
		if len(record) == 0 {
			continue
		}
		if err := emit(provider, id, record); err != nil {
			return fmt.Errorf("emit failed: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("(*sql.Rows).Err failed: %w", err)
	}

	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <provider> <image>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	provider := os.Args[1]
	ref, err := name.ParseReference(os.Args[2])
	if err != nil {
		log.Fatalf("name.ParseReference failed: %v", err)
	}

	if err := export(ctx, provider, ref); err != nil {
		log.Fatal(err)
	}
}

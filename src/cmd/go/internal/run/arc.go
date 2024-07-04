package run

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// extractURL downloads and extracts archive from a given URL to a directory.
// Supported schemes: http, https, file
// Supported archive format/extension: .tar, .zip, .tar.gz/.tgz
func extractURL(archiveURL string, dir string, headers []string, insecure bool) error {
	u, err := url.Parse(archiveURL)
	if err != nil {
		return err
	}

	switch u.Scheme {
	case "http", "https":
		return extractWebResource(u, dir, headers, insecure)
	case "file":
		return extractLocalFile(u.Path, dir)
	default:
		return fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
}

func extractWebResource(u *url.URL, dir string, headers []string, insecure bool) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	cli := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}

	for _, h := range headers {
		kv := strings.SplitN(h, ":", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid header: %s", h)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		req.Header.Add(k, v)
	}

	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download %v, status: %s", u, resp.Status)
	}

	switch t := resp.Header.Get("Content-Type"); {
	case strings.Contains(t, "application/x-tar") ||
		strings.HasSuffix(u.Path, ".tar"):
		if err := untar(resp.Body, dir); err != nil {
			return err
		}
	case strings.Contains(t, "application/zip") ||
		strings.HasSuffix(u.Path, ".zip"):
		if err := unzip(resp.Body, dir); err != nil {
			return err
		}
	case strings.Contains(t, "application/x-gzip") ||
		strings.HasSuffix(u.Path, ".tar.gz") ||
		strings.HasSuffix(u.Path, ".tgz"):
		if err := gunzip(resp.Body, dir); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported archive format: %s", t)
	}

	return nil
}

func extractLocalFile(file string, dir string) error {
	r, err := os.Open(file)
	if err != nil {
		return err
	}
	defer r.Close()

	switch {
	case strings.HasSuffix(file, ".tar"):
		if err := untar(r, dir); err != nil {
			return err
		}
	case strings.HasSuffix(file, ".zip"):
		if err := unzip(r, dir); err != nil {
			return err
		}
	case strings.HasSuffix(file, ".tar.gz") ||
		strings.HasSuffix(file, ".tgz"):
		if err := gunzip(r, dir); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported archive format: %s", filepath.Ext(file))
	}
	return nil
}

func unzip(r io.Reader, dir string) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		p := filepath.Join(dir, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(p, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(p), os.ModePerm)
			f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, f.Mode())
			if err != nil {
				return err
			}
			defer f.Close()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func untar(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		p := filepath.Join(dir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, p); err != nil {
				return err
			}
		default:
			return fmt.Errorf("header type not supported: %v %q", header.Typeflag, p)
		}
	}
	return nil
}

func gunzip(r io.Reader, dir string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()
	return untar(gr, dir)
}

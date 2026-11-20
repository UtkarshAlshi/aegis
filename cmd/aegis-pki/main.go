package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegis/internal/clock"
	"aegis/internal/pki"
)

const maxCertificate = 256 << 10

func create(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	err = errors.Join(err, f.Sync(), f.Close())
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func writePair(dir, base string, pair pki.Pair) error {
	key := filepath.Join(dir, base+".key")
	if err := create(key, pair.Key); err != nil {
		return err
	}
	if err := create(filepath.Join(dir, base+".crt"), pair.Certificate); err != nil {
		_ = os.Remove(key)
		return err
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: aegis-pki init-ca | issue server|client | revoke")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", ".", "PKI directory")
	c := clock.Real{}
	switch args[0] {
	case "init-ca":
		lifetime := flags.Duration("ttl", 365*24*time.Hour, "CA TTL")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return errors.New("usage: init-ca [-dir DIR] [-ttl DURATION]")
		}
		pair, err := pki.NewCA(c, *lifetime)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(*dir, 0700); err != nil {
			return err
		}
		revocations := filepath.Join(*dir, "revoked.txt")
		if err = create(revocations, nil); err != nil {
			return err
		}
		if err = writePair(*dir, "ca", pair); err != nil {
			_ = os.Remove(revocations)
			return err
		}
		return nil
	case "issue":
		lifetime := flags.Duration("ttl", 24*time.Hour, "leaf TTL")
		sans := flags.String("sans", "", "comma-separated DNS names or IPs")
		name := flags.String("name", "", "client service name")
		out := flags.String("out", "", "output basename")
		if len(args) < 2 || (args[1] != "server" && args[1] != "client") || flags.Parse(args[2:]) != nil || flags.NArg() != 0 {
			return errors.New("usage: issue server|client [-dir DIR] [-out BASENAME] [-ttl DURATION] [-sans DNS,IP | -name SERVICE]")
		}
		kind := args[1]
		if *out == "" {
			*out = kind
		}
		if filepath.Base(*out) != *out || strings.ContainsAny(*out, "\\/:") || *out == "." || *out == ".." {
			return errors.New("invalid output basename")
		}
		caPair, err := pki.LoadPair(filepath.Join(*dir, "ca.crt"), filepath.Join(*dir, "ca.key"))
		if err != nil {
			return err
		}
		ca, err := pki.ParseCA(c, caPair)
		if err != nil {
			return err
		}
		var pair pki.Pair
		if kind == "server" {
			if *name != "" {
				return errors.New("use -sans with server certificates")
			}
			pair, err = ca.IssueServer(strings.Split(*sans, ","), *lifetime)
		} else {
			if *sans != "" {
				return errors.New("use -name with client certificates")
			}
			pair, err = ca.IssueClient(*name, *lifetime)
		}
		if err != nil {
			return err
		}
		return writePair(*dir, *out, pair)
	case "revoke":
		certFile := flags.String("cert", "", "path to issued certificate")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *certFile == "" {
			return errors.New("usage: revoke [-dir DIR] -cert FILE")
		}
		raw, err := pki.ReadFile(*certFile, maxCertificate)
		if err != nil {
			return err
		}
		cert, err := pki.ParseCertificate(raw)
		if err != nil {
			return err
		}
		raw, err = pki.ReadFile(filepath.Join(*dir, "ca.crt"), maxCertificate)
		if err != nil {
			return err
		}
		ca, err := pki.ParseCertificate(raw)
		if err != nil || cert.IsCA || cert.CheckSignatureFrom(ca) != nil {
			return errors.New("certificate was not issued by this CA")
		}
		return pki.Revoke(filepath.Join(*dir, "revoked.txt"), pki.SerialHex(cert))
	default:
		return errors.New("unknown PKI command")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

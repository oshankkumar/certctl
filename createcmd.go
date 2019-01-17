package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewCreateCmd() *cobra.Command {
	opts := CreateOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create self signed certificate and key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.RunCreate()
		},
	}
	cmd.Flags().StringArrayVar(&opts.IPAddresses, "endpoints", []string{"127.0.0.1"}, "ipaddrs of servers where this cert will be used")
	cmd.Flags().StringVar(&opts.KeyFile, "keyout", "ca.key", "file path to store private key")
	cmd.Flags().StringVar(&opts.CertFile, "certout", "ca.crt", "file path to store certificate")
	return cmd
}

type CreateOptions struct {
	IPAddresses []string
	KeyFile     string
	CertFile    string
	cert        []byte
	key         []byte
}

func (opts *CreateOptions) RunCreate() error {
	var (
		addresses  []net.IP
		privKeyBuf = &bytes.Buffer{}
		certBuf    = &bytes.Buffer{}
	)
	log.WithFields(log.Fields{
		"ip":        opts.IPAddresses,
		"key-file":  opts.KeyFile,
		"cert-file": opts.CertFile,
	}).Debug("options used")

	privKey, err := CreateRSAKeyPair(rand.Reader, 2048, privKeyBuf)
	if err != nil {
		return err
	}

	log.Debug("\n", privKeyBuf.String())

	for _, addr := range opts.IPAddresses {
		addresses = append(addresses, net.ParseIP(addr))
	}

	log.Debug("addr: ", addresses)
	certTmpl, err := CertTemplate(true, addresses)
	if err != nil {
		return err
	}

	certTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	certTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	_, err = CreateCert(certTmpl, certTmpl, &privKey.PublicKey, privKey, certBuf)
	if err != nil {
		return err
	}

	log.Debug("\n", certBuf.String())

	opts.key = privKeyBuf.Bytes()
	opts.cert = certBuf.Bytes()

	return opts.SaveToFile()
}

func (opts *CreateOptions) SaveToFile() error {
	for _, crt := range []struct {
		file    string
		content []byte
	}{
		{opts.KeyFile, opts.key},
		{opts.CertFile, opts.cert},
	} {
		file, err := os.OpenFile(crt.file, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := file.Write(crt.content); err != nil {
			return err
		}
	}
	return nil
}

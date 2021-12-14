package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/ironiridis/util/env"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	InstanceID string `json:"i"`
	Hostname   string `json:"d"`
	KeyName    string `json:"k"`
	Username   string `json:"u"`
	State      string `json:"s"`
	Port       string `json:"P"`
	client     *ssh.Client
	sshkey     ssh.Signer
}

var homedir = env.GetString("HOME", ".")
var keydir = env.GetString("SSH_KEY_LOCATION", homedir+"/.ssh")
var keyext = env.GetString("SSH_KEY_EXT", ".pem")

func (h *Host) getKey() (err error) {
	if h.sshkey != nil {
		return nil
	}
	fn := keydir + "/" + h.KeyName + keyext
	keybytes, err := ioutil.ReadFile(fn)
	if err != nil {
		err = fmt.Errorf("error reading key file %q: %w", fn, err)
		return
	}
	h.sshkey, err = ssh.ParsePrivateKey(keybytes)
	if err != nil {
		err = fmt.Errorf("error parsing key file %q: %w", fn, err)
	}
	return
}

func (h *Host) Usable() bool {
	if h.State != "" && h.State != "running" {
		return false
	}
	if h.Hostname == "" {
		return false
	}
	return true
}

func (h *Host) Close() error {
	r := h.client.Close()
	h.client = nil
	return r
}

func (h *Host) Dial() error {
	if h.Hostname == "" {
		return fmt.Errorf("no hostname -- is the host running?")
	}

	var err error
	if h.Username == "" {
		h.Username = env.GetString("SSH_DEFAULT_USERNAME", "ubuntu")
	}
	if h.Port == "" {
		h.Port = env.GetString("SSH_DEFAULT_PORT", "22")
	}
	hp := net.JoinHostPort(h.Hostname, h.Port)

	err = h.getKey()
	if err != nil {
		return fmt.Errorf("error getting key for %q: %w", hp, err)
	}
	conf := &ssh.ClientConfig{
		User:            h.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(h.sshkey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	h.client, err = ssh.Dial("tcp", hp, conf)
	if err != nil {
		return fmt.Errorf("error Dialing %q: %w", hp, err)
	}
	return nil
}

func (h *Host) Run(cmd string) ([]byte, []byte, error) {
	var err error
	if h.client == nil {
		err = h.Dial()
		if err != nil {
			return nil, nil, err
		}
	}
	sesh, err := h.client.NewSession()
	if err != nil {
		h.client.Close()
		return nil, nil, fmt.Errorf("error opening a session with %q: %w", h.client.RemoteAddr(), err)
	}
	defer sesh.Close()
	var cmdstdout bytes.Buffer
	sesh.Stdout = &cmdstdout
	var cmdstderr bytes.Buffer
	sesh.Stderr = &cmdstderr
	err = sesh.Run(cmd)
	return cmdstdout.Bytes(), cmdstderr.Bytes(), err
}

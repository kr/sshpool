package sshpool_test

import (
	"bytes"
	"os"

	"github.com/kr/sshpool"
	"golang.org/x/crypto/ssh"
)

var config = &ssh.ClientConfig{
	User: "username",
	Auth: []ssh.ClientAuth{
		// ClientAuthPassword wraps a ClientPassword implementation
		// in a type that implements ClientAuth.
		ssh.ClientAuthPassword(password("yourpassword")),
	},
}

func Example() {
	sess, err := sshpool.Open("tcp", "127.0.0.1:22", config)
	if err != nil {
		panic(err)
	}

	var b bytes.Buffer
	sess.Stdout = &b
	err = sess.Run("ls")
	if err != nil {
		panic(err)
	}
	os.Stdout.Write(b.Bytes())
}

type password string

func (p password) Password(user string) (string, error) {
	return string(p), nil
}

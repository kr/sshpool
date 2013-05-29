package sshpool_test

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"github.com/kr/sshpool"
	"os"
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

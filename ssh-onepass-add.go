package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var pubKey = flag.String("public-key", "", "Public key or key signature")
var vault = flag.String("vault", "Private", "Vault name")
var pwName = flag.String("pw-name", "", "Password name in vault")

func main() {
	flag.Parse()
	if *pubKey == "" || *pwName == "" {
		log.Fatal("Must provide -public-key -pw-name")
	}

	if os.Getenv("OP_SESSION_slacksec") == "" {
		log.Fatal("Must onepassword before running sshagentbuddy")
	}

	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	entries, err := ioutil.ReadDir(sshDir)
	if err != nil {
		log.Fatalf("Failed to read ~/.ssh directory: %s", err)
	}

	var privateKeyData []byte
	var fullPublicKey ssh.PublicKey

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pub") {
			fpath := filepath.Join(sshDir, entry.Name())

			pubData, err := ioutil.ReadFile(fpath)
			if err != nil {
				log.Printf("Failed to read key %s: %s", fpath, err)
				continue
			}
			k, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
			if err != nil {
				log.Printf("Failed to parse public key %s: %s", fpath, err)
				continue
			}

			if publicKeyMatches(k, *pubKey) {
				fullPublicKey = k
				privateKeyName := strings.TrimSuffix(fpath, ".pub")
				privateKeyData, err = ioutil.ReadFile(privateKeyName)
				if err != nil {
					log.Fatalf("Failed to read private key %s for matching public key: %s", privateKeyName, err)
				}
				break
			}
		}
	}

	if len(privateKeyData) == 0 {
		log.Fatalf("Failed to find matching key for %s", *pubKey)
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	agentClient := agent.NewClient(conn)

	keys, err := agentClient.List()
	if err != nil {
		panic(err)
	}
	for _, key := range keys {
		if bytes.Equal(key.Blob, fullPublicKey.Marshal()) {
			fmt.Println("Key already loaded, loading anyways")
		}
	}

	cmd := exec.Command("/usr/local/bin/op", "get", "item", "--vault", *vault, *pwName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Ooops: %s\n", out)
		panic(err)
	}

	var opData PwData
	err = json.Unmarshal(out, &opData)
	if err != nil {
		panic(err)
	}

	key, err := ssh.ParseRawPrivateKeyWithPassphrase(privateKeyData, []byte(opData.Details.Password))
	if err != nil {
		panic(err)
	}

	agentKey := agent.AddedKey{
		PrivateKey: key,
	}
	err = agentClient.Add(agentKey)
	if err != nil {
		panic(err)
	}
}

// Matches public keys of the following formats:
// SHA256:K9iDay9EhqzjORPiV7gBuk2Fi7ip/EFpFv+adJOl/+A
// 0c:6a:f7:40:5a:d8:9d:aa:68:7d:e2:d7:0e:7a:0c:49
// AAAAC3NzaC1lZDI1NTE5AAAAINP1mclTzyApP1GoAF2y/Kn2eYP5pk7HIJvIyUS7Ugbb
func publicKeyMatches(k ssh.PublicKey, s string) bool {
	return ssh.FingerprintSHA256(k) == s ||
		ssh.FingerprintLegacyMD5(k) == s ||
		base64.RawStdEncoding.EncodeToString(k.Marshal()) == s
}

type PwData struct {
	ChangerUUID string `json:"changerUuid"`
	CreatedAt   string `json:"createdAt"`
	Details     struct {
		Fields     []interface{} `json:"fields"`
		NotesPlain string        `json:"notesPlain"`
		Password   string        `json:"password"`
		Sections   []interface{} `json:"sections"`
	} `json:"details"`
	ItemVersion int64 `json:"itemVersion"`
	Overview    struct {
		Ainfo string        `json:"ainfo"`
		Pbe   float64       `json:"pbe"`
		Pgrng bool          `json:"pgrng"`
		Ps    int64         `json:"ps"`
		Tags  []interface{} `json:"tags"`
		Title string        `json:"title"`
		URL   string        `json:"url"`
	} `json:"overview"`
	TemplateUUID string `json:"templateUuid"`
	Trashed      string `json:"trashed"`
	UpdatedAt    string `json:"updatedAt"`
	UUID         string `json:"uuid"`
	VaultUUID    string `json:"vaultUuid"`
}

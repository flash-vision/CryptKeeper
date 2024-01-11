package cryptkeeper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type ConfigFile struct {
	FilePath       string
	EnvironmentVar string
}

func NewConfigFile(filePath string, isEncrypt bool, environmentVar string) *ConfigFile {
	return &ConfigFile{
		FilePath:       filePath,
		EnvironmentVar: environmentVar,
	}
}
func (c *ConfigFile) ProcessFile() error {
	key := os.Getenv(c.EnvironmentVar)

	// Read the source file
	fileContent, err := ioutil.ReadFile(c.FilePath)
	if err != nil {
		log.Printf("Failed to read file: %s, error: %v\n", c.FilePath, err)
		return err
	}

	var result []byte
	var newFilePath string

	if strings.HasSuffix(c.FilePath, ".crypt") {
		// Decrypt the file content
		result, err = decrypt(fileContent, key)
		if err != nil {
			log.Printf("Failed to decrypt file: %v\n", err)
			return err
		}
		newFilePath = strings.TrimSuffix(c.FilePath, ".crypt")
	} else {
		// Encrypt the file content
		result, err = encrypt(fileContent, key)
		if err != nil {
			log.Printf("Failed to encrypt file: %v\n", err)
			return err
		}
		newFilePath = c.FilePath + ".crypt"
	}

	// Write the result to the new file
	err = ioutil.WriteFile(newFilePath, result, 0644)
	if err != nil {
		log.Printf("Failed to write to file: %s, error: %v\n", newFilePath, err)
		return err
	}

	// Remove the original file
	if err := os.Remove(c.FilePath); err != nil {
		log.Printf("Failed to remove the original file: %s, error: %v\n", c.FilePath, err)
		return err
	}

	// Update the FilePath to the new file's path
	c.FilePath = newFilePath

	return nil
}

func createHash(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	key := createHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := createHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Repurposed crypter function
func (c *ConfigFile) Crypter() {
	if len(os.Getenv(c.EnvironmentVar)) == 0 {
		log.Fatal("Encryption key is not set.")
		os.Exit(1)
	}

	err := c.ProcessFile()
	if err != nil {
		log.Fatalf("Failed to process file: %v", err)
	}

	log.Printf("Processed file written to: %s\n", c.FilePath)
}

func LoadConfig(configPath string) (map[any]interface{}, error) {
	configMap := make(map[any]any)
	viper.SetConfigFile(configPath)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	//load the config data into the configMap map
	for _, key := range viper.AllKeys() {
		configMap[key] = viper.GetString(key)
	}
	// print out all the key/values in the configMap neatly
	for key, value := range configMap {
		fmt.Printf("%s = %v\n", key, value)
	}
	//materialize the variabls into a map
	return configMap, nil

}

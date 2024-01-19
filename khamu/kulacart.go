package khamu

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

// Note: This package doesn't work any longer because login requires
// 2FA.

const (
	loginUrl         = "https://%s/admin/login.php"
	updateInstallUrl = "https://%s/api/v1/installs/update/1"
)

type KhamuClient struct {
	client   *http.Client
	lastBody io.Reader
	hostname string
}

func NewKhamuClient(hostname string) *KhamuClient {
	cj, _ := cookiejar.New(nil)
	return &KhamuClient{
		client:   &http.Client{Jar: cj},
		hostname: hostname,
	}
}

func (c *KhamuClient) Login(username, password string) error {
	res, err := c.client.PostForm(fmt.Sprintf(loginUrl, c.hostname), url.Values{
		"username": []string{username},
		"password": []string{password},
		"submit":   []string{""},
	})
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Invalid status code for login (%d): %w", res.StatusCode, err)
	}

	// Limit response size to 100kB, these responses should always be <~1k
	d, err := io.ReadAll(io.LimitReader(res.Body, 100000))
	if err != nil {
		return err
	}

	c.lastBody = bytes.NewBuffer(d)

	return nil
}

func (c *KhamuClient) GetInstallData() (KhamuInstallData, error) {
	if c.lastBody == nil {
		return nil, fmt.Errorf("No data from Khamu. Login first")
	}

	return KhamuInstallDataFromPage(c.lastBody)
}

func (c *KhamuClient) UpdateInstallData(d KhamuInstallData) error {
	ip, ct, err := d.HttpPostPayload()
	if err != nil {
		return err
	}

	res, err := c.client.Post(fmt.Sprintf(updateInstallUrl, c.hostname), ct, ip)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Invalid status code for login (%d): %w", res.StatusCode, err)
	}

	return nil
}

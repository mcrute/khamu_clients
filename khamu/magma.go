package khamu

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const (
	magmaRoot        = "https://magma.k2magma.com/"
	magmaUserLogin   = "https://magma.k2magma.com/users/login"
	magmaApiLogin    = "https://magma.k2magma.com/api/v1/user/login"
	magmaManager     = "https://magma.k2magma.com/manager"
	magmaItemSales   = "https://magma.k2magma.com/api/v1/reports/report/itemSales"
	magmaSettings    = "https://magma.k2magma.com/api/v1/users/%d"
	magmaDateUpdate  = "https://magma.k2magma.com/api/v1/users/updateDefaultDates/%d"
	keyTemplate      = "https://magma.k2magma.com~::~%s"
	csrfLinePrefix   = "<script>"
	csrfLineSuffix   = "</script>"
	cryptoKeyVarName = "window._mtoken"
	csrfBlobVarName  = "window.ksu"
	chromeUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
)

type MagmaClient struct {
	client      *http.Client
	session     MagmaSession
	csrfToken   string
	cryptoToken string
}

func NewMagmaClient() *MagmaClient {
	cj, _ := cookiejar.New(nil)
	return &MagmaClient{client: &http.Client{Jar: cj}}
}

// initializeState is responsible for getting the cookies and the CSRF
// token from the server for the first time and storing them for later
// use. This is required before any other call otherwise the server will
// return login and CSRF errors.
func (c *MagmaClient) initializeState() error {
	// Get cookies and the document to extract the coken from
	res, err := c.client.Get(magmaUserLogin)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// CSRF token is encrypted as JSON in the document. Part of the crypto
	// key is a javascript string. We need to extract these and decrypt the
	// CSRF token to continue. The crypto key will also be used to encrypt
	// the username/password for login.
	var tokens map[string]string
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, csrfLinePrefix) {
			line = strings.TrimPrefix(line, csrfLinePrefix)
			line = strings.TrimSuffix(line, csrfLineSuffix)
			if !strings.HasPrefix(line, cryptoKeyVarName) {
				continue
			}
			if tokens, err = c.extractTokens(line); err != nil {
				return fmt.Errorf("MagmaClient.initializeState: error extracting tokens: %w", err)
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("MagmaClient.initializeState: error scanning document: %w", err)
	}

	if ct, ok := tokens[cryptoKeyVarName]; ok {
		c.cryptoToken = ct
	} else {
		return fmt.Errorf("MagmaClient.initializeState: crypto token not found in document")
	}

	csrfBlob, ok := tokens[csrfBlobVarName]
	if !ok {
		return fmt.Errorf("MagmaClient.initializeState: encrypted csrf blob not found in document")
	}

	if ct, err := c.extractCsrfToken(csrfBlob); err != nil {
		return fmt.Errorf("MagmaClient.initializeState: failed to decrypt csrf token: %w", err)
	} else {
		c.csrfToken = ct
	}

	return nil
}

func (c *MagmaClient) cryptoKey() string {
	return fmt.Sprintf(keyTemplate, c.cryptoToken)
}

func (c *MagmaClient) extractCsrfToken(jsonString string) (string, error) {
	b64json, err := decrypt(jsonString, c.cryptoKey())
	if err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(b64json)
	if err != nil {
		return "", err
	}

	var t struct {
		Token string `json:"_token"`
	}

	if err := json.Unmarshal(decoded, &t); err != nil {
		return "", err
	}

	return t.Token, nil
}

func (c *MagmaClient) extractTokens(line string) (map[string]string, error) {
	out := map[string]string{}

	// Split on the javascript delimiter
	for _, p := range strings.Split(line, ";") {
		// More than twice and we can falsely split on base64 padding
		kv := strings.SplitN(p, "=", 2)

		// There is a trailing semicolon, so ignore that 1-item slice
		if len(kv) != 2 {
			continue
		}

		// Strip space from the keys and the ``s from the values
		out[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), "`")
	}

	return out, nil
}

func (c *MagmaClient) Login(username, password string) error {
	if err := c.initializeState(); err != nil {
		return fmt.Errorf("MagmaClient.Login: error initializing state: %w", err)
	}

	encEmail, err := encrypt(username, c.cryptoKey())
	if err != nil {
		return fmt.Errorf("MagmaClient.Login: error encrypting email: %w", err)
	}

	encPass, err := encrypt(password, c.cryptoKey())
	if err != nil {
		return fmt.Errorf("MagmaClient.Login: error encrypting password: %w", err)
	}

	form, _ := json.Marshal(map[string]string{
		"email_e":    encEmail,
		"password_e": encPass,
	})

	req, err := http.NewRequest(http.MethodPost, magmaApiLogin, bytes.NewBuffer(form))
	if err != nil {
		return fmt.Errorf("MagmaClient.Login: error building http request: %w", err)
	}
	req.Header.Add("User-Agent", chromeUserAgent)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("csrftoken", c.csrfToken)

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("MagmaClient.Login: Invalid status code for login (%d): %w", res.StatusCode, err)
	}

	login := RawMagmaLogin{}
	if err = json.NewDecoder(res.Body).Decode(&login); err != nil {
		return fmt.Errorf("MagmaClient.Login: error decoding login JSON: %w", err)
	}

	if !login.IsValidResponse() {
		return fmt.Errorf("MagmaClient.Login: Magma returned invalid login response %#v", login)
	}

	c.session = login.ToSession()

	return nil
}

func (c *MagmaClient) doApiRequest(reqUrl, method string, out interface{}, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, reqUrl, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", chromeUserAgent)
	req.Header.Add("X-Authorization", c.session.Key)
	req.Header.Add("csrftoken", c.csrfToken)

	if method != http.MethodGet {
		req.Header.Add("Content-Type", "application/json")
	} else {
		req.Header.Add("Accept", "application/json")
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if out != nil {
		if err = json.NewDecoder(res.Body).Decode(out); err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (c *MagmaClient) GetItemSales() (*MagmaItemSales, error) {
	sales := &MagmaItemSales{}
	_, err := c.doApiRequest(magmaItemSales, http.MethodGet, sales, nil)
	if err != nil {
		return nil, err
	}
	if sales.Error != nil {
		return nil, fmt.Errorf("MagmaClient.GetItemSales: Magma returned error %s %s", sales.Error.Code, sales.Error.Message)
	}
	return sales, nil
}

func (c *MagmaClient) getSettings() (map[string]map[string]interface{}, error) {
	val := map[string]map[string]interface{}{}
	_, err := c.doApiRequest(fmt.Sprintf(magmaSettings, c.session.UserId), http.MethodGet, &val, nil)
	if err != nil {
		return nil, err
	}
	if err, ok := val["error"]; ok {
		return nil, fmt.Errorf("Magma returned error: %#v", err)
	}
	if _, ok := val["data"]; !ok {
		return nil, fmt.Errorf("Maga returned unknown response: %#v", val)
	}
	return val, nil
}

func (c *MagmaClient) SetReportDates(start, end time.Time) (err error) {
	// What we're doing here is inherently pretty fragile and therefore
	// dangerous; we need to fail cleanly to prevent panic-ing the
	// entire server. Several consumers of this client run in background
	// goroutines that have no panic handling logic.
	//
	// We need the entire JSON response returned by Magma so that we can
	// delete a few keys and also set a few keys as their web client does.
	// The catch is that we need to re-POST the entire payload to the
	// server with only those modifications, while also preserving all the
	// other fields, otherwise we will corrupt the Magma server state (it
	// has no PATCH semantics).
	//
	// The fragile/dangerous bit is that the format may change at any time
	// without any warning.
	//
	// No metrics are logged here because the top-level logic using this
	// client logs its own metrics and errors here will appear in those
	// failure metrics.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("MagmaClient.SetReportDates: Panic: %#v", r)
		}
	}()

	cfg, err := c.getSettings()
	if err != nil {
		return err
	}

	sites := cfg["data"]["sites"].([]interface{})

	for _, s := range sites {
		s := s.(map[string]interface{})
		delete(s, "last_updated")
		delete(s, "reportsOn")
	}

	cfg["data"]["apps"] = nil
	cfg["data"]["_method"] = "PUT"
	cfg["data"]["default_from"] = fmt.Sprintf("%sT00:00:00.000Z", start.Format("2006-01-02"))
	cfg["data"]["default_to"] = fmt.Sprintf("%sT00:00:00.000Z", end.Format("2006-01-02"))
	cfg["data"]["dates"] = map[string]string{
		"startDate": start.Format("2006-01-02"),
		"endDate":   end.Format("2006-01-02"),
	}

	jo, err := json.Marshal(cfg["data"])
	if err != nil {
		return err
	}

	_, err = c.doApiRequest(
		fmt.Sprintf(magmaDateUpdate, c.session.UserId),
		http.MethodPut,
		nil,
		bytes.NewBuffer(jo))

	return err
}

func (c *MagmaClient) SetReportDatesCurrentMonth() error {
	y, m, _ := time.Now().Date()
	return c.SetReportDatesMonth(y, int(m))
}

func (c *MagmaClient) SetReportDatesMonth(year, month int) error {
	start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local)
	end := start.AddDate(0, 1, 0).Add(-time.Nanosecond)
	return c.SetReportDates(start, end)
}

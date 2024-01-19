package khamu

import (
	"encoding/json"
	"strconv"
	"strings"
)

type MagmaError struct {
	Code     string `json:"code"`
	HttpCode int    `json:"http_code"`
	Message  string `json:"message"`
}

// RawMagmaLogin is the subset of the login response we need to make
// further requests to the API. The rest of the items in the response
// don't matter to us.
//
// The methods on this struct try to hide the ugliness of the underlying
// API from the rest of the application.
type RawMagmaLogin struct {
	Data struct {
		Api struct {
			UserId int    `json:"user_id"`
			Key    string `json:"key"`
		} `json:"api"`
		Message string `json:"message"`
	} `json:"data"`
}

func (l *RawMagmaLogin) IsValidResponse() bool {
	return l.Data.Api.UserId != 0 && l.Data.Api.Key != ""
}

func (l *RawMagmaLogin) ToSession() MagmaSession {
	return MagmaSession{l.Data.Api.UserId, l.Data.Api.Key}
}

type MagmaSession struct {
	UserId int
	Key    string
}

type MagmaRange struct {
	StartDate      string  `json:"start_date"` // 2021-08-31
	EndDate        string  `json:"end_date"`
	AfterDiscounts float64 `json:"after_disc"`
	AfterTaxes     float64 `json:"after_taxes"`
}

type MagmaItem struct {
	CategoryName string  `json:"cat_name"`
	Description  string  `json:"descr"`
	Count        int     `json:"count"`
	Quantity     int     `json:"qty"`
	Sales        float64 `json:"sales"`
	Size         string  `json:"size"`
	Discount     float64 `json:"disc"`
	NetSales     float64 `json:"net_sales"`
	Extern       string  `json:"extern"`
}

func (i *MagmaItem) IsMilkshake() bool {
	return strings.Contains(strings.ToLower(i.Description), "shake")
}

func (i *MagmaItem) UnmarshalJSON(d []byte) error {
	type Alias MagmaItem

	v := &struct {
		*Alias
		Count interface{} `json:"count"`
	}{Alias: (*Alias)(i)}

	if err := json.Unmarshal(d, v); err != nil {
		return err
	}

	// Magma plays fast and loose with the type of Count
	switch c := v.Count.(type) {
	case int64:
		i.Count = int(c)
	case int:
		i.Count = c
	case float64:
		i.Count = int(c)
	case string:
		f, err := strconv.ParseFloat(c, 64)
		if err == nil {
			i.Count = int(f)
		}
	}

	return nil
}

type MagmaItemSales struct {
	Series []string      `json:"series"`
	Range  MagmaRange    `json:"range"`
	Sales  [][]MagmaItem `json:"sales"`
	Error  *MagmaError   `json:"error"`
}

func (s *MagmaItemSales) GetMilkshakeSales() int {
	sum := 0

	for _, i := range s.Sales[0] {
		if i.IsMilkshake() {
			sum += i.Count
		}
	}

	return sum
}

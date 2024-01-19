package khamu

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	orderMessage       = "Online Ordering is currently unavailable. Please come back later."
	payloadContentType = "application/json"
	installPrefix      = "window.$install = "
	installSuffix      = ";"
)

type KhamuOrderState int

const (
	KhamuOrdersActive KhamuOrderState = iota
	KhamuOrdersInactive
	KhamuOrdersInconsistent
)

type KhamuInstallData map[string]interface{}

func KhamuInstallDataFromPage(page io.Reader) (KhamuInstallData, error) {
	rd := bufio.NewReader(page)
	jd := KhamuInstallData{}

	for {
		l, err := rd.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("Error reading document: %w", err)
		} else if err != nil && err == io.EOF {
			return nil, fmt.Errorf("Content not found in document, EOF")
		}

		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, installPrefix) {
			res := strings.TrimPrefix(l, installPrefix)
			res = strings.TrimSuffix(l, installSuffix)

			if err := json.Unmarshal([]byte(res), &jd); err != nil {
				return nil, fmt.Errorf("Error decoding json: %w", err)
			}

			return jd, nil
		}
	}
}

func (d KhamuInstallData) getJsonInt(k string) (int, bool) {
	if vr, ok := d[k]; ok {
		if v, ok := vr.(int); ok {
			return v, true
		} else {
			return 0, false
		}
	} else {
		return 0, false
	}
}

func (d KhamuInstallData) GetOrderState() KhamuOrderState {
	active, ok := d.getJsonInt("active")
	if !ok {
		return KhamuOrdersInconsistent
	}
	pickUp, ok := d.getJsonInt("pick_up")
	if !ok {
		return KhamuOrdersInconsistent
	}
	delivery, ok := d.getJsonInt("delivery")
	if !ok {
		return KhamuOrdersInconsistent
	}
	dineIn, ok := d.getJsonInt("dineln")
	if !ok {
		return KhamuOrdersInconsistent
	}

	if active == 0 && pickUp == 0 && delivery == 0 && dineIn == 0 {
		return KhamuOrdersInactive
	} else if active == 1 && pickUp == 1 && delivery == 1 && dineIn == 1 {
		return KhamuOrdersActive
	} else {
		return KhamuOrdersInconsistent
	}
}

func (d KhamuInstallData) updateJsonState(v int) {
	d["active"] = v
	d["pick_up"] = v
	d["delivery"] = v
	d["dineln"] = v
	d["offline_message"] = orderMessage
}

func (d KhamuInstallData) DisableOrdering() {
	d.updateJsonState(0)
}

func (d KhamuInstallData) EnableOrdering() {
	d.updateJsonState(1)
}

func (d KhamuInstallData) HttpPostPayload() (io.Reader, string, error) {
	i, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}

	return bytes.NewReader(i), payloadContentType, nil
}

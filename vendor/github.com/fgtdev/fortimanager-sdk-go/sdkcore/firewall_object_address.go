package fmgclient

import (
	"fmt"

	"github.com/fgtdev/fortimanager-sdk-go/util"
)

// JSONFirewallObjectAddress contains the params for creating firewall object address
type JSONFirewallObjectAddress struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Comment        string `json:"comment"`
	Fqdn           string `json:"fqdn"`
	AssociatedIntf string `json:"associated-interface"`
	Subnet         string `json:"subnet"`
	StartIp        string `json:"start-ip"`
	EndIp          string `json:"end-ip"`
	AllowRouting   string `json:"allow-routing"`
}

// CreateUpdateFirewallObjectAddress is for creating/updating the firewall object address
// Input:
//   @params: infor needed
//   @method: operation method, "add" or "update"
// Output:
//   @err: error details if failure, and nil if success
func (c *FmgSDKClient) CreateUpdateFirewallObjectAddress(params *JSONFirewallObjectAddress, method string) (err error) {
	defer c.Trace("CreateUpdateFirewallObjectAddress")()

	p := map[string]interface{}{
		"data": params,
		"url":  "/pm/config/adom/root/obj/firewall/address",
	}

	_, err = c.Do(method, p)

	if err != nil {
		err = fmt.Errorf("CreateUpdateFirewallObjectAddress failed: %s", err)
		return
	}

	return
}

// ReadFirewallObjectAddress is for reading the specific firewall object address
// Input:
//   @name: firewall object addesss name
// Output:
//   @out: firewall object address infor
//   @err: error details if failure, and nil if success
func (c *FmgSDKClient) ReadFirewallObjectAddress(name string) (out *JSONFirewallObjectAddress, err error) {
	defer c.Trace("ReadFirewallObjectAddress")()

	p := map[string]interface{}{
		"url": "/pm/config/adom/root/obj/firewall/address/" + name,
	}

	result, err := c.Do("get", p)
	if err != nil {
		err = fmt.Errorf("ReadFirewallObjectAddress failed :%s", err)
		return
	}

	data := (result["result"].([]interface{}))[0].(map[string]interface{})["data"].(map[string]interface{})
	if data == nil {
		err = fmt.Errorf("cannot get the results from the response")
		return
	}

	out = &JSONFirewallObjectAddress{}
	if data["name"] != nil {
		out.Name = data["name"].(string)
	}
	if data["type"] != nil {
		out.Type = util.FirewallObjectAddrType2Str(int(data["type"].(float64)))
	}
	if data["comment"] != nil {
		out.Comment = data["comment"].(string)
	}
	if data["fqdn"] != nil {
		out.Fqdn = data["fqdn"].(string)
	}

	if data["associated-interface"] != nil {
		m := util.InterfaceArray2StrArray(data["associated-interface"].([]interface{}))
		// only 1 item is allowed here
		out.AssociatedIntf = m[0]
	}
	if data["subnet"] != nil {
		sn := data["subnet"].([]interface{})
		out.Subnet = sn[0].(string) + " " + sn[1].(string)
	}
	if data["start-ip"] != nil {
		out.StartIp = data["start-ip"].(string)
	}
	if data["end-ip"] != nil {
		out.EndIp = data["end-ip"].(string)
	}
	if data["allow-routing"] != nil {
		out.AllowRouting = util.ControlSwitch2Str(int(data["allow-routing"].(float64)))
	}

	return
}

// DeleteFirewallObjectAddress is for deleting the specific firewall object address
// Input:
//   @name: firewall object addesss name
// Output:
//   @err: error details if failure, and nil if success
func (c *FmgSDKClient) DeleteFirewallObjectAddress(name string) (err error) {
	defer c.Trace("DeleteFirewallObjectAddress")()

	p := map[string]interface{}{
		"url": "/pm/config/adom/root/obj/firewall/address/" + name,
	}

	_, err = c.Do("delete", p)
	if err != nil {
		err = fmt.Errorf("DeleteFirewallObjectAddress failed :%s", err)
		return
	}

	return
}

package fortios

import (
	"fmt"
	"log"

	"github.com/fgtdev/fortios-sdk-go/sdkcore"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceSystemSettingDNS() *schema.Resource {
	return &schema.Resource{
		Create: resourceSystemSettingDNSCreateUpdate,
		Read:   resourceSystemSettingDNSRead,
		Update: resourceSystemSettingDNSCreateUpdate,
		Delete: resourceSystemSettingDNSDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"primary": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "208.91.112.53",
			},
			"secondary": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "208.91.112.52",
			},
		},
	}
}

func resourceSystemSettingDNSCreateUpdate(d *schema.ResourceData, m interface{}) error {
	mkey := d.Id()

	c := m.(*FortiClient).Client
	c.Retries = 1

	//Get Params from d
	primary := d.Get("primary").(string)
	secondary := d.Get("secondary").(string)

	//Build input data by sdk
	i := &forticlient.JSONSystemSettingDNS{
		Primary:   primary,
		Secondary: secondary,
	}

	//Call process by sdk
	_, err := c.UpdateSystemSettingDNS(i, mkey)
	if err != nil {
		return fmt.Errorf("Error updating System Setting DNS: %s", err)
	}

	d.SetId(primary)

	return resourceSystemSettingDNSRead(d, m)
}

func resourceSystemSettingDNSDelete(d *schema.ResourceData, m interface{}) error {
	// no API for this
	return nil
}

func resourceSystemSettingDNSRead(d *schema.ResourceData, m interface{}) error {
	mkey := d.Id()

	c := m.(*FortiClient).Client
	c.Retries = 1

	//Call process by sdk
	o, err := c.ReadSystemSettingDNS(mkey)
	if err != nil {
		return fmt.Errorf("Error reading System Setting DNS: %s", err)
	}

	if o == nil {
		log.Printf("[WARN] resource (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	//Refresh property
	d.Set("primary", o.Primary)
	d.Set("secondary", o.Secondary)

	return nil
}

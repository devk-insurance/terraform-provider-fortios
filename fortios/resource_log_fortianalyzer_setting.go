package fortios

import (
	"fmt"
	"log"

	"github.com/fgtdev/fortios-sdk-go/sdkcore"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceLogFortiAnalyzerSetting() *schema.Resource {
	return &schema.Resource{
		Create: resourceLogFortiAnalyzerSettingCreateUpdate,
		Read:   resourceLogFortiAnalyzerSettingRead,
		Update: resourceLogFortiAnalyzerSettingCreateUpdate,
		Delete: resourceLogFortiAnalyzerSettingDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"status": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"server": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0.0.0.0",
			},
			"source_ip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
			},
			"upload_option": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "5-minute",
			},
			"reliable": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "disable",
			},
			"hmac_algorithm": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "sha256",
			},
			"enc_algorithm": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "high",
			},
		},
	}
}

func resourceLogFortiAnalyzerSettingCreateUpdate(d *schema.ResourceData, m interface{}) error {
	mkey := d.Id()
	c := m.(*FortiClient).Client
	c.Retries = 1

	//Get Params from d
	status := d.Get("status").(string)
	server := d.Get("server").(string)
	sourceIP := d.Get("source_ip").(string)
	uploadOption := d.Get("upload_option").(string)
	reliable := d.Get("reliable").(string)
	hmacAlgorithm := d.Get("hmac_algorithm").(string)
	encAlgorithm := d.Get("enc_algorithm").(string)

	//Build input data by sdk
	i := &forticlient.JSONLogFortiAnalyzerSetting{
		Status:        status,
		Server:        server,
		SourceIP:      sourceIP,
		UploadOption:  uploadOption,
		Reliable:      reliable,
		HmacAlgorithm: hmacAlgorithm,
		EncAlgorithm:  encAlgorithm,
	}

	//Call process by sdk
	_, err := c.UpdateLogFortiAnalyzerSetting(i, mkey)
	if err != nil {
		return fmt.Errorf("Error updating Log FortiAnalyzer Setting: %s", err)
	}

	d.SetId(server)

	return resourceLogFortiAnalyzerSettingRead(d, m)
}

func resourceLogFortiAnalyzerSettingDelete(d *schema.ResourceData, m interface{}) error {
	// no API for this
	return nil
}

func resourceLogFortiAnalyzerSettingRead(d *schema.ResourceData, m interface{}) error {
	mkey := d.Id()

	c := m.(*FortiClient).Client
	c.Retries = 1

	//Call process by sdk
	o, err := c.ReadLogFortiAnalyzerSetting(mkey)
	if err != nil {
		return fmt.Errorf("Error reading Log FortiAnalyzer Setting: %s", err)
	}

	if o == nil {
		log.Printf("[WARN] resource (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	//Refresh property
	d.Set("status", o.Status)
	d.Set("server", o.Server)
	d.Set("source_ip", o.SourceIP)
	d.Set("upload_option", o.UploadOption)
	d.Set("reliable", o.Reliable)
	d.Set("hmac_algorithm", o.HmacAlgorithm)
	d.Set("enc_algorithm", o.EncAlgorithm)

	return nil
}

package main

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/hooklift/gowsdl/soap"
	"github.com/reguero/goauthor/landbsoap/networkservice"
)

func main() {
	client := soap.NewClient(
		"https://cstest.cern.ch/sc/soap/soap.fcgi?v=6&WSDL",
		//"https://network.cern.ch/sc/soap/soap.fcgi?v=5&WSDL",
		soap.WithTimeout(time.Second*5),
		soap.WithBasicAuth("xxxx", "yyy"),
		soap.WithTLS(&tls.Config{InsecureSkipVerify: true}),
	)
	service := networkservice.NewNetworkServiceInterface(client)
	var auth networkservice.Auth
	authstr := "xxxx,yyyyy,NICE"

	//authtoken, err := service.GetAuthToken(&authstr)
	if err := client.Call("GetAuthToken", &authstr, &auth.Token); err != nil {
		log.Fatalf("could't get auth token: %v", err)
	}
	//auth.Token = *authtoken
	reply, err := service.GetDeviceInfo(&auth)
	if err != nil {
		log.Fatalf("could't get device info: %v", err)
	}
	log.Println(reply)
}

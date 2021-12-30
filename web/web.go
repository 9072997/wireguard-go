package web

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type confHandler struct {
	*device.Device
}

func Serve(listen string, device *device.Device) error {
	mux := http.NewServeMux()
	mux.Handle("/", confHandler{device})
	return http.ListenAndServe(listen, mux)
}

func (dev confHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	serverPub := dev.PublicKey()
	clientPub, clientPriv, err := newKeypair()
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte(err.Error()))
		return
	}
	clientIP := dev.AutoIPv6(device.NoisePublicKey(clientPub))

	resp.Write([]byte(
		`[Interface]
PrivateKey = ` + clientPriv.String() + `
Address = ` + clientIP.String() + `/128

[Peer]
PublicKey = ` + b64Str(serverPub[:]) + `
AllowedIPs = ::/1, 8000::/1
Endpoint = ` + req.Host + `:` + fmt.Sprint(dev.ListenPort()) + ``,
	))
}

func newKeypair() (pub wgtypes.Key, priv wgtypes.Key, err error) {
	priv, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return pub, priv, err
	}
	pub = priv.PublicKey()
	return
}

func b64Str(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

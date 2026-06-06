package solver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type chromeTransport struct {
	proxy *url.URL
	h2t   *http2.Transport
}

func newChromeTransport(proxyURL string) (*chromeTransport, error) {
	ct := &chromeTransport{}
	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("solver: invalid proxy URL: %w", err)
		}
		ct.proxy = pu
	}
	ct.h2t = &http2.Transport{
		DialTLSContext:     ct.dialTLSContext,
		MaxHeaderListSize:  262144,
		DisableCompression: false,
	}
	return ct, nil
}

func (ct *chromeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return ct.h2t.RoundTrip(req)
}

func (ct *chromeTransport) dialTLSContext(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	var rawConn net.Conn
	var err error

	if ct.proxy != nil {
		rawConn, err = ct.dialViaProxy(ctx, addr)
	} else {
		rawConn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)
	uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	return uConn, nil
}

func (ct *chromeTransport) dialViaProxy(ctx context.Context, addr string) (net.Conn, error) {
	proxyAddr := ct.proxy.Host
	if ct.proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyAddr, "80")
	}

	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if ct.proxy.User != nil {
		user := ct.proxy.User.Username()
		pass, _ := ct.proxy.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy response: %w", err)
	}
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp[:min(len(resp), 80)])
	}
	return conn, nil
}

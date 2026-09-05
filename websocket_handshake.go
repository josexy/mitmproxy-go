package mitmproxy

import (
	"bufio"
	"bytes"

	http "github.com/josexy/xhttp"
)

// The WebSocket upgrader replays a parsed response's captured header block.
// Rebuild that block from the sanitized Header map so removed hop-by-hop fields
// cannot reappear. Retain the original response for interceptor wire metadata.
func websocketResponseForUpgrade(response *http.Response) (*http.Response, error) {
	copyResponse := *response
	copyResponse.Body = http.NoBody
	copyResponse.ContentLength = 0
	copyResponse.Close = false
	copyResponse.TransferEncoding = nil
	copyResponse.Trailer = nil
	var wire bytes.Buffer
	writer := &http1ResponseWriter{dst: &wire, order: responseHeaderOrder(response).Headers}
	if err := copyResponse.Write(writer); err != nil {
		return nil, err
	}
	if err := writer.flush(); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(&wire), response.Request)
}

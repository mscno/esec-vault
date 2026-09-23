package broker

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client talks to a running broker over its unix socket.
type Client struct {
	SockPath string
	// Timeout bounds the whole request round trip. Requests that may wait for
	// interactive approval should set this above the server's ApproveTimeout.
	Timeout time.Duration
}

// NewClient returns a client for the broker at sockPath.
func NewClient(sockPath string) *Client {
	return &Client{SockPath: sockPath, Timeout: 10 * time.Second}
}

// Call sends one request and reads one response.
func (c *Client) Call(req *Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.SockPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("broker not reachable at %s (is 'esec-vault agent' running?): %w", c.SockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read broker response: %w", err)
	}
	return &resp, nil
}

// Ping checks the broker is alive.
func (c *Client) Ping() error {
	resp, err := c.Call(&Request{Op: OpPing})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("broker ping failed: %s", resp.Error)
	}
	return nil
}

// GetSecrets asks the broker to decrypt the secrets file at path and returns
// the resulting environment map. Callers waiting on approvals should set a
// generous Timeout.
func (c *Client) GetSecrets(project, env, path, format string) (map[string]string, error) {
	resp, err := c.Call(&Request{Op: OpGetSecrets, Project: project, Env: env, Path: path, Format: format})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Secrets, nil
}

// Approve grants a pending approval by id.
func (c *Client) Approve(id string) error {
	resp, err := c.Call(&Request{Op: OpApprove, ID: id})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

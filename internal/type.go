package internal

type Vault struct {
	Salt       string  `json:"salt"`
	WrappedDEK string  `json:"wrapped_dek"`
	NonceDEK   string  `json:"nonce_dek"`
	Version    string  `json:"version"`
	CreatedAt  int64   `json:"created_at"`
	Entries    []Entry `json:"entries"`
}

type Entry struct {
	ID       string `json:"id"`
	Site     string `json:"site"`
	Username string `json:"username"`
	Password string `json:"password"`
}

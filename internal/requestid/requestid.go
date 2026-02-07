package requestid

import (
	"net/http"

	"github.com/google/uuid"
)

// Header is the HTTP header carrying request IDs.
const Header = "X-Request-Id"

func New() string {
	return uuid.NewString()
}

// Ensure returns the request ID from the request or generates a new one.
// It also writes the request ID to the response header when provided.
func Ensure(w http.ResponseWriter, r *http.Request) string {
	if r == nil {
		id := New()
		if w != nil {
			w.Header().Set(Header, id)
		}
		return id
	}

	id := r.Header.Get(Header)
	if id == "" {
		id = New()
		r.Header.Set(Header, id)
	}
	if w != nil {
		w.Header().Set(Header, id)
	}

	return id
}

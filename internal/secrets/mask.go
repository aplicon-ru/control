package secrets

// Mask redacts a secret value for display in logs and SSE streams (spec
// §6). Empty stays empty so a masked frame for an unset field doesn't
// render "****" next to something that's actually blank.
func Mask(s string) string {
	if s == "" {
		return ""
	}
	return "****"
}

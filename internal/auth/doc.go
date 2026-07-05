// Package auth implements local password authentication, JWT access
// tokens backed by revocable opaque refresh sessions, org-scoped
// role-based access control (super_admin / org_admin / operator /
// viewer), and IP allowlisting. See spec §3.
//
// OIDC, TOTP 2FA, password reset, and HTTP middleware wiring are not
// implemented here yet — see the package's issue history for why each is
// deferred.
package auth

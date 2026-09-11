package net.secureauth.auth;

/**
 * Authentication states of a connected player.
 *
 * <pre>
 * UNREGISTERED → REGISTERING → AUTHENTICATED
 * UNREGISTERED → (register) → REGISTERED_NOT_AUTHENTICATED → (login) → AUTHENTICATED
 * any unauthenticated state → LOCKED (temporary lockout or admin lock)
 * </pre>
 *
 * The state is maintained server-side only; the client is never trusted to
 * report its own authentication state.
 */
public enum AuthState {
	/** A brand-new identity: no account exists yet. */
	UNREGISTERED,

	/** A registration attempt is in progress (screen open / confirmation pending). */
	REGISTERING,

	/** An account exists but this connection has not proven the password. */
	REGISTERED_NOT_AUTHENTICATED,

	/** The connection proved the password and was restored to the real world. */
	AUTHENTICATED,

	/** Account locked (temporary lockout or administrator action). */
	LOCKED;

	/** True while the player must stay inside the pre-authentication sandbox. */
	public boolean isUnauthenticated() {
		return this != AUTHENTICATED;
	}
}

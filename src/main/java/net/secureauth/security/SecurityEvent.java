package net.secureauth.security;

/**
 * Types of security-relevant events written by {@link SecurityLogger}.
 * Never includes password material — by construction.
 */
public enum SecurityEvent {

	ACCOUNT_REGISTERED("A player registered a new account"),
	LOGIN_SUCCESS("A player authenticated successfully"),
	LOGIN_FAILURE("A login attempt failed"),
	ACCOUNT_LOCKED("An account entered a temporary lockout"),
	ACCOUNT_UNLOCKED("An account lockout was lifted"),
	ACCOUNT_PERMANENTLY_LOCKED("An account was permanently locked"),
	PASSWORD_CHANGED("A password was changed"),
	ADMIN_RESET("An administrator reset an account"),
	ADMIN_UNREGISTER("An administrator deleted an account"),
	ADMIN_FORCE_LOGOUT("An administrator forced a player back to the auth area"),
	SESSION_RESUMED("A returning player was auto-authenticated by the IP-bound session resume"),
	AUTH_TIMEOUT("A player was disconnected for not authenticating in time"),
	PLAYER_QUARANTINED("A player entered the pre-authentication sandbox"),
	AUTH_STATE_RESTORED("A player was restored to the real world"),
	REGISTRATION_REJECTED("A registration attempt was rejected"),
	COMMAND_BLOCKED("A command was blocked before authentication"),
	SANDBOX_ESCAPE_CORRECTED("Unauthorised movement was corrected"),
	INVALID_AUTH_PACKET("An invalid or abusive panel interaction arrived"),
	PANEL_OPENED("A chest panel was opened"),
	DATABASE_UNAVAILABLE("The account database failed"),
	CONFIG_ERROR("A configuration problem was detected"),
	SERVER_STOPPED("The server stopped; all sessions invalidated");

	private final String description;

	SecurityEvent(String description) {
		this.description = description;
	}

	public String description() {
		return description;
	}
}

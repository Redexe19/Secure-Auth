package net.secureauth.network;

/**
 * Marks packets sent by SecureAuth itself so the outgoing-packet filter lets
 * them through even while the viewer is unauthenticated (auth prompts, the
 * tab-list hiding packet itself, etc.). All uses are on the server thread.
 */
public final class PacketBypass {

	private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

	private PacketBypass() {
	}

	/** Runs {@code action} with the packet filter bypassed for this thread. */
	public static void run(Runnable action) {
		DEPTH.set(DEPTH.get() + 1);
		try {
			action.run();
		} finally {
			int depth = DEPTH.get() - 1;
			if (depth <= 0) {
				DEPTH.remove();
			} else {
				DEPTH.set(depth);
			}
		}
	}

	public static boolean isBypassed() {
		return DEPTH.get() > 0;
	}
}

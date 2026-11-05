package jp.gekko11.insurerlogin;

import java.util.function.Predicate;

/**
 * 防御が有効か。secure の版は、常に有効のままである。
 * vulnerable の版だけ、実行中に外す部品（src/vulnerable）が判定を差し替える（D-20）。
 */
public final class Defenses {

	/** ログインサーバーで外せる防御（scenarios の 2-3）。 */
	public static final String AUD_ONE = "D3a";

	public static final String SHORT_TTL = "D3b";

	public static final String ID_TOKEN_AUD = "D3c";

	private static volatile Predicate<String> enabled = (id) -> true;

	private Defenses() {
	}

	public static boolean enabled(String id) {
		return enabled.test(id);
	}

	public static void use(Predicate<String> predicate) {
		enabled = predicate;
	}

}

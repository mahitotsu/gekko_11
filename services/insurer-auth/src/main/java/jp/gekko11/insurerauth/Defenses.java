package jp.gekko11.insurerauth;

/**
 * 防御が有効か。secure の版は、常に有効を返す（SecureDefenses）。
 * vulnerable の版だけ、実行中に外せる実装（src/vulnerable/java）を足す（D-20）。
 */
public interface Defenses {

	/** 認可サーバーで外せる防御（scenarios の 2-3）。 */
	String AUD_ONE = "D3a";

	String SHORT_TTL = "D3b";

	String ID_TOKEN_AUD = "D3c";

	String KEEP_ACT = "D3d";

	String NARROW_TERMS = "D3e";

	String FIXED_TARGET = "D3f";

	boolean enabled(String id);

}

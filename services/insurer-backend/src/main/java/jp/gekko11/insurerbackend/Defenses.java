package jp.gekko11.insurerbackend;

import java.util.Optional;

/**
 * 防御が有効か。secure の版は、常に有効を返す（SecureDefenses）。
 * vulnerable の版だけ、実行中に外せる実装（src/vulnerable/java）を足す（D-20）。
 */
public interface Defenses {

	/** 保険会社のシステムで外せる防御（scenarios の 2-3）。 */
	String CUSTOMER_FROM_SUB = "D9";

	String VERIFIED_FROM_TOKEN = "D11";

	String OFFER_SIGNATURE = "D12";

	String PASSKEY_SEAL = "D13";

	String SEAL_CHAIN = "D14";

	String TERMS_RANGE = "D15";

	String NONCE_ONCE = "D16";

	String DERIVE_RECORD = "D17";

	String REGISTERED_CONTACT = "D18";

	boolean enabled(String id);

	/** 外したときの外し方（D13 は "off"、"mtls-only"、"agent-signed"）。 */
	Optional<String> variant(String id);

}

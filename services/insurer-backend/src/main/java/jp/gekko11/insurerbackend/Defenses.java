package jp.gekko11.insurerbackend;

import java.util.Optional;

/**
 * 防御が有効か。secure の版は、常に有効を返す（SecureDefenses）。
 * vulnerable の版だけ、実行中に外せる実装（src/vulnerable/java）を足す（D-24）。
 */
public interface Defenses {

	/** 保険会社のシステムで外せる防御（scenarios の 2-3）。 */
	String CUSTOMER_FROM_SUB = "G9";

	String VERIFIED_FROM_TOKEN = "G11";

	String OFFER_SIGNATURE = "G12";

	String PASSKEY_SEAL = "G13";

	String SEAL_CHAIN = "G14";

	String TERMS_RANGE = "G15";

	String NONCE_ONCE = "G16";

	String DERIVE_RECORD = "G17";

	String REGISTERED_CONTACT = "G18";

	String OFFER_CONTENT = "G30";

	boolean enabled(String id);

	/** 外したときの外し方（G13 は "off"、"mtls-only"、"agent-signed"）。 */
	Optional<String> variant(String id);

}

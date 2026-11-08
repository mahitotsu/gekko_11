package jp.gekko11.insurerbackend;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

/** テスト用のソフトウェアの認証器。顧客の passkey の代わりに、内容のハッシュ（challenge）へ署名する。 */
final class SoftAuthenticator {

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private final KeyPair keys;

	private final byte[] credentialId;

	private final String rpId;

	private final String origin;

	private int counter;

	SoftAuthenticator(String rpId, String origin) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		this.keys = generator.generateKeyPair();
		this.credentialId = MessageDigest.getInstance("SHA-256").digest(this.keys.getPublic().getEncoded());
		this.rpId = rpId;
		this.origin = origin;
	}

	private SoftAuthenticator(SoftAuthenticator same, String origin) {
		this.keys = same.keys;
		this.credentialId = same.credentialId;
		this.rpId = same.rpId;
		this.origin = origin;
	}

	/** 同じ passkey を、別の画面（origin）で使う。ログインの画面で作る署名に当たる。 */
	SoftAuthenticator on(String origin) {
		return new SoftAuthenticator(this, origin);
	}

	/** 認可サーバーが渡す形の、登録済みの公開鍵。 */
	Map<String, String> registered() {
		byte[] cose = new ObjectConverter().getCborConverter()
			.writeValueAsBytes(EC2COSEKey.create((ECPublicKey) this.keys.getPublic(), COSEAlgorithmIdentifier.ES256));
		return Map.of("id", B64.encodeToString(this.credentialId), "coseKey", B64.encodeToString(cose));
	}

	/** WebAuthn の assertion（JSON の形）。challenge は base64url の文字列。 */
	Map<String, Object> sign(String challenge) throws Exception {
		byte[] clientData = ("{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + this.origin
				+ "\"}")
			.getBytes(StandardCharsets.UTF_8);
		byte[] rpIdHash = MessageDigest.getInstance("SHA-256").digest(this.rpId.getBytes(StandardCharsets.UTF_8));
		byte[] authData = ByteBuffer.allocate(37).put(rpIdHash).put((byte) 0x05).putInt(++this.counter).array();
		Signature signer = Signature.getInstance("SHA256withECDSA");
		signer.initSign(this.keys.getPrivate());
		signer.update(authData);
		signer.update(MessageDigest.getInstance("SHA-256").digest(clientData));
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("clientDataJSON", B64.encodeToString(clientData));
		response.put("authenticatorData", B64.encodeToString(authData));
		response.put("signature", B64.encodeToString(signer.sign()));
		Map<String, Object> assertion = new LinkedHashMap<>();
		assertion.put("id", B64.encodeToString(this.credentialId));
		assertion.put("rawId", B64.encodeToString(this.credentialId));
		assertion.put("type", "public-key");
		assertion.put("response", response);
		assertion.put("clientExtensionResults", Map.of());
		return assertion;
	}

}

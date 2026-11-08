package jp.gekko11.insurerbackend;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.BadOriginException;

import org.springframework.stereotype.Component;

/**
 * 申込みと意向確認の署名を確かめる。署名は 2 つのことを同時に示す（D-1、D13）。
 * <ul>
 * <li>誰が承認したか: 本人が登録した passkey で署名されている</li>
 * <li>何を承認したか: 署名が、内容の正規化のハッシュ（challenge）に結び付いている</li>
 * </ul>
 * 同期される passkey は署名回数が 0 のままなので、回数では重複を見ない。重複は nonce で防ぐ（D16）。
 * 教材のための意図的に悪い確かめ方（mtls-only、agent-signed）を含む。本番の部品として使わないこと。
 */
@Component
class Seals {

	record Result(boolean ok, String detail) {
	}

	/** 「営業 AI エージェント自身が署名したので正しい」とする悪い例のための、教材用の固定の公開鍵。 */
	private static final String AGENT_PUBLIC_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
			+ "\"x\":\"lylaMtu9oZ56ueH5q4j3jpKuORqMClepmfv-D7PWrZ4\",\"y\":\"hYmLAA7SDD7GnmDTPTgG65zMSGqaxcS_TpICtiK3GdI\"}";

	private final WebAuthnManager webAuthn = WebAuthnManager.createNonStrictWebAuthnManager();

	private final ObjectConverter converter = new ObjectConverter();

	private final ObjectMapper json = new ObjectMapper();

	private final PasskeyDirectory passkeys;

	private final BackendProperties props;

	Seals(BackendProperties props, PasskeyDirectory passkeys) {
		this.props = props;
		this.passkeys = passkeys;
	}

	/**
	 * passkey の署名。公開鍵は、ログインサーバーに登録された passkey のものを、認可サーバーを通して引く（4-5、D-42）。
	 * 同じ passkey はログインにも使うので、署名した画面（origin）が顧客のアプリであることも確かめる。
	 */
	Result passkey(Object content, Object assertion, String user) {
		if (!(assertion instanceof Map<?, ?> a) || a.get("id") == null) {
			return new Result(false, "署名（assertion）がない");
		}
		try {
			String assertionJson = this.json.writeValueAsString(assertion);
			AuthenticationData parsed = this.webAuthn.parseAuthenticationResponseJSON(assertionJson);
			List<Map<String, String>> keys = this.passkeys.keysOf(user);
			Map<String, String> key = keys.stream()
				.filter((k) -> Arrays.equals(b64(k.get("id")), parsed.getCredentialId()))
				.findFirst()
				.orElse(null);
			if (key == null) {
				return new Result(false, user + " が登録した passkey の署名ではない");
			}
			COSEKey cose = this.converter.getCborConverter().readValue(b64(key.get("coseKey")), COSEKey.class);
			CredentialRecordImpl credential = new CredentialRecordImpl(new NoneAttestationStatement(), null, null, null,
					0, new AttestedCredentialData(AAGUID.ZERO, parsed.getCredentialId(), cose), null, null, null, null);
			Set<Origin> origins = this.props.origins().stream().map(Origin::new).collect(Collectors.toSet());
			ServerProperty server = new ServerProperty(origins, this.props.rpId(),
					new DefaultChallenge(Canonical.digest(content)));
			this.webAuthn.verifyAuthenticationResponseJSON(assertionJson,
					new AuthenticationParameters(server, credential, null, true));
			return new Result(true, "内容は署名時のまま");
		}
		catch (BadOriginException ex) {
			return new Result(false, "顧客のアプリの画面で作った署名ではない（ログインの画面などで作った署名は、申込みの署名にならない）");
		}
		catch (Exception ex) {
			String m = String.valueOf(ex.getMessage());
			return new Result(false, m.toLowerCase().contains("challenge") ? "署名が内容と一致しない（内容が署名時と違う）"
					: "署名の検証に失敗: " + m);
		}
	}

	/** 悪い例 1: 信頼する事務サービス（mTLS）から届いたので、中身を見ずに受け付ける。 */
	Result mtlsOnly(String peer) {
		return this.props.spiffeId("insurer-mcp").equals(peer) ? new Result(true, "信頼する事務サービスから届いた（中身は見ていない）")
				: new Result(false, "信頼する事務サービスからではない");
	}

	/** 悪い例 2: 営業 AI エージェントが申込みに署名したので、正しいとみなす。書き換えた本人かもしれない。 */
	Result agentSigned(Object content, Object assertion) {
		try {
			JWSObject jws = JWSObject.parse(String.valueOf(assertion));
			boolean ok = jws.verify(new ECDSAVerifier(ECKey.parse(AGENT_PUBLIC_JWK)))
					&& new String(jws.getPayload().toBytes(), StandardCharsets.UTF_8).equals(Canonical.of(content));
			return ok ? new Result(true, "営業 AI エージェントの署名と一致した（誰の意思かは見ていない）")
					: new Result(false, "営業 AI エージェントの署名と一致しない");
		}
		catch (Exception ex) {
			return new Result(false, "営業 AI エージェントの署名が不正");
		}
	}

	private static byte[] b64(String value) {
		return Base64.getUrlDecoder().decode(value);
	}

}

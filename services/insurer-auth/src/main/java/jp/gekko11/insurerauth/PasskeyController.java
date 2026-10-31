package jp.gekko11.insurerauth;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 顧客の passkey を登録し、保険会社のシステムに公開鍵を渡す（D-1、D13）。
 * 登録は、ログインした顧客だけが行う。公開鍵の参照は、保険会社のシステムの SPIFFE ID だけが行える。
 */
@RestController
class PasskeyController {

	record Credential(byte[] id, byte[] coseKey) {
	}

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private final WebAuthnManager webAuthn = WebAuthnManager.createNonStrictWebAuthnManager();

	private final ObjectConverter converter = new ObjectConverter();

	private final Map<String, List<Credential>> credentials = new ConcurrentHashMap<>();

	private final Map<String, byte[]> challenges = new ConcurrentHashMap<>();

	private final AuthProperties props;

	PasskeyController(AuthProperties props) {
		this.props = props;
	}

	@PostMapping("/passkeys/register/options")
	Map<String, Object> options(Principal user) {
		byte[] challenge = new DefaultChallenge().getValue();
		this.challenges.put(user.getName(), challenge);
		return Map.of("challenge", B64.encodeToString(challenge),
				"rp", Map.of("id", this.props.rpId(), "name", "教材保険会社"),
				"user", Map.of("id", B64.encodeToString(user.getName().getBytes()), "name", user.getName(),
						"displayName", user.getName()),
				"pubKeyCredParams", List.of(Map.of("type", "public-key", "alg", -7)),
				"authenticatorSelection", Map.of("residentKey", "preferred", "userVerification", "required"),
				"attestation", "none");
	}

	@PostMapping("/passkeys/register/verify")
	ResponseEntity<?> verify(Principal user, @RequestBody String responseJson) {
		byte[] challenge = this.challenges.remove(user.getName());
		if (challenge == null) {
			return ResponseEntity.badRequest().body(Map.of("error", "登録の準備がない"));
		}
		Set<Origin> origins = this.props.origins().stream().map(Origin::new).collect(Collectors.toSet());
		ServerProperty server = new ServerProperty(origins, this.props.rpId(), new DefaultChallenge(challenge));
		RegistrationData data;
		try {
			data = this.webAuthn.verifyRegistrationResponseJSON(responseJson, new RegistrationParameters(server, true));
		}
		catch (RuntimeException ex) {
			return ResponseEntity.badRequest().body(Map.of("error", "検証に失敗した: " + ex.getMessage()));
		}
		AttestedCredentialData attested = data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
		byte[] coseKey = this.converter.getCborConverter().writeValueAsBytes(attested.getCOSEKey());
		this.credentials.computeIfAbsent(user.getName(), (k) -> new ArrayList<>())
			.add(new Credential(attested.getCredentialId(), coseKey));
		return ResponseEntity.ok(Map.of("ok", true));
	}

	@GetMapping("/internal/passkeys/{user}")
	ResponseEntity<?> lookup(@PathVariable String user, HttpServletRequest request) {
		if (!PeerIdentity.is(request, this.props.spiffeId("insurer-backend"))) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "保険会社のシステムではない"));
		}
		return ResponseEntity.ok(this.credentials.getOrDefault(user, List.of())
			.stream()
			.map((c) -> Map.of("id", B64.encodeToString(c.id()), "coseKey", B64.encodeToString(c.coseKey())))
			.toList());
	}

}

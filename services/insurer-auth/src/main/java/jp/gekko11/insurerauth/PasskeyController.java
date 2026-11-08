package jp.gekko11.insurerauth;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 顧客の受信箱の番号（直送の宛先）を、本人が登録した連絡先として受け取る（P-14、D-26）。登録は、ログインサーバーが出した P を示した顧客だけが行う（D-42）。本人には、自分の passkey の一覧も返す（D-43）。
 * 保険会社のシステムには、連絡先と、利用者の passkey の公開鍵を渡す（D-1、D13）。passkey は、ログインサーバーが登録を持ち、そこから読む（D-42）。
 * 参照は、保険会社のシステムの SPIFFE ID だけが行える。
 */
@RestController
class PasskeyController {

	/** 顧客ごとの受信箱の番号（直送の宛先）。端末ごとに登録し、全てに送る。 */
	private final Map<String, Set<String>> inboxes = new ConcurrentHashMap<>();

	/** 受信箱の番号は、推測できない長さの base64url（128 ビット以上）に限る。 */
	private static final java.util.regex.Pattern INBOX = java.util.regex.Pattern.compile("[A-Za-z0-9_-]{22,64}");

	private final AuthProperties props;

	private final LoginDirectory directory;

	PasskeyController(AuthProperties props, LoginDirectory directory) {
		this.props = props;
		this.directory = directory;
	}

	/** 本文は {inbox: 受信箱の番号}。顧客のアプリの BFF が、ログインの後に、端末の番号を登録する。 */
	@PostMapping("/contacts/inbox")
	ResponseEntity<?> registerInbox(Principal user, @RequestBody Map<String, Object> body) {
		if (!(body.get("inbox") instanceof String inbox) || !INBOX.matcher(inbox).matches()) {
			return ResponseEntity.badRequest().body(Map.of("error", "受信箱の番号がない"));
		}
		this.inboxes.computeIfAbsent(user.getName(), (k) -> ConcurrentHashMap.newKeySet()).add(inbox);
		return ResponseEntity.ok(Map.of("ok", true));
	}

	/** ログインした本人が登録した受信箱の番号の一覧。 */
	@GetMapping("/contacts/mine")
	Map<String, Object> mine(Principal user) {
		return Map.of("inboxes", List.copyOf(this.inboxes.getOrDefault(user.getName(), Set.of())));
	}

	/** ログインした本人の passkey の一覧（D-43）。顧客のアプリの BFF が、ログインの直後に P で読む。公開鍵は返さない。 */
	@GetMapping("/passkeys/mine")
	ResponseEntity<?> myPasskeys(Principal user) {
		try {
			return ResponseEntity.ok(this.directory.listOf(user.getName()));
		}
		catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", "ログインサーバーから passkey を読めない: " + ex.getMessage()));
		}
	}

	@GetMapping("/internal/contacts/{user}")
	ResponseEntity<?> contact(@PathVariable String user, HttpServletRequest request) {
		if (!PeerIdentity.is(request, this.props.spiffeId("insurer-backend"))) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "保険会社のシステムではない"));
		}
		return ResponseEntity.ok(Map.of("inboxes", List.copyOf(this.inboxes.getOrDefault(user, Set.of()))));
	}

	@GetMapping("/internal/passkeys/{user}")
	ResponseEntity<?> lookup(@PathVariable String user, HttpServletRequest request) {
		if (!PeerIdentity.is(request, this.props.spiffeId("insurer-backend"))) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "保険会社のシステムではない"));
		}
		try {
			return ResponseEntity.ok(this.directory.keysOf(user));
		}
		catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", "ログインサーバーから passkey を読めない: " + ex.getMessage()));
		}
	}

}

package jp.gekko11.insurerauth;

import java.security.Principal;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * 利用者の passkey を、ログインサーバーから読んで取り次ぐ。登録は、ログインサーバーが持つ（D-42）。
 * 本人には、自分の passkey の一覧を返す（D-43）。保険会社のシステムには、利用者の passkey の公開鍵を渡す（D-1、G13）。
 * 公開鍵の参照は、保険会社のシステムの SPIFFE ID だけが行える。
 */
@RestController
class PasskeyController {

	private final AuthProperties props;

	private final LoginDirectory directory;

	PasskeyController(AuthProperties props, LoginDirectory directory) {
		this.props = props;
		this.directory = directory;
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

package jp.gekko11.insurerbackend;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * 契約の記録と直送の記録を、監査の役にだけ見せる（D-17、P-7）。トークンは使わず、相手の SPIFFE ID（auditor）で限る。
 * Envoy は、この受け口にだけ、相手の証明書の情報（XFCC）を渡す。
 */
@RestController
class AuditController {

	private final Store store;

	private final BackendProperties props;

	AuditController(Store store, BackendProperties props) {
		this.store = store;
		this.props = props;
	}

	@GetMapping("/audit/records")
	ResponseEntity<?> records(@RequestHeader(name = "x-forwarded-client-cert", required = false) String xfcc) {
		if (!this.props.spiffeId("auditor").equals(uri(xfcc))) {
			return ResponseEntity.status(403).body(Map.of("error", "監査の役ではない"));
		}
		return ResponseEntity.ok(Map.of("contracts", this.store.contracts, "outbox", this.store.outbox));
	}

	/** Envoy の XFCC（SANITIZE_SET）から、相手の SPIFFE ID を読む。 */
	static String uri(String xfcc) {
		if (xfcc == null) {
			return null;
		}
		for (String part : xfcc.split(",")[0].split(";")) {
			if (part.startsWith("URI=")) {
				return part.substring(4).replace("\"", "");
			}
		}
		return null;
	}

}

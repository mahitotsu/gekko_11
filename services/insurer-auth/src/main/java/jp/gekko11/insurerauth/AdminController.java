package jp.gekko11.insurerauth;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 運用の受け口。営業 AI エージェントなどの登録を外し、また戻す（G4、P-13）。
 * 呼べるのは、運用の担当の SPIFFE ID（operator）だけである。secure にもある運用の機能である。
 */
@RestController
class AdminController {

	private final ClientRevocation revocation;

	private final RegisteredClientRepository clients;

	private final AuthProperties props;

	AdminController(ClientRevocation revocation, RegisteredClientRepository clients, AuthProperties props) {
		this.revocation = revocation;
		this.clients = clients;
		this.props = props;
	}

	@PostMapping("/admin/clients/{id}/revoke")
	ResponseEntity<?> revoke(@PathVariable String id, HttpServletRequest request) {
		return change(id, request, true);
	}

	@PostMapping("/admin/clients/{id}/restore")
	ResponseEntity<?> restore(@PathVariable String id, HttpServletRequest request) {
		return change(id, request, false);
	}

	private ResponseEntity<?> change(String id, HttpServletRequest request, boolean revoke) {
		if (!PeerIdentity.is(request, this.props.spiffeId("operator"))) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "運用の担当ではない"));
		}
		if (this.clients.findByClientId(id) == null) {
			return ResponseEntity.notFound().build();
		}
		if (revoke) {
			this.revocation.revoke(id);
		}
		else {
			this.revocation.restore(id);
		}
		return ResponseEntity.ok(Map.of("client_id", id, "revoked", revoke));
	}

}

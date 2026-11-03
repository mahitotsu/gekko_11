package jp.gekko11.insureraudit;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

/** 監査の画面（契約の一覧と、契約ごとの突き合わせ）と、同じ中身の JSON の受け口。役割が監査の者だけが使える（SecurityConfig）。 */
@Controller
class AuditController {

	private static final int LIST_LIMIT = 30;

	private static final ObjectMapper JSON = new ObjectMapper();

	private final Reconciler reconciler;

	AuditController(Reconciler reconciler) {
		this.reconciler = reconciler;
	}

	@GetMapping("/")
	String contracts(Model model, @AuthenticationPrincipal OidcUser user) {
		model.addAttribute("user", user.getSubject());
		model.addAttribute("contracts", this.reconciler.list(LIST_LIMIT));
		return "contracts";
	}

	@GetMapping("/contracts/{nonce}")
	String contract(@PathVariable String nonce, Model model, @AuthenticationPrincipal OidcUser user) {
		model.addAttribute("user", user.getSubject());
		model.addAttribute("report", found(nonce));
		model.addAttribute("pretty", new Pretty());
		return "contract";
	}

	/** 記録を、画面に整えた JSON で出す。 */
	public static final class Pretty {

		public String of(Object value) {
			try {
				return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(value);
			}
			catch (Exception ex) {
				return String.valueOf(value);
			}
		}

	}

	@GetMapping("/api/contracts")
	@ResponseBody
	List<Reconciler.Summary> contractsJson() {
		return this.reconciler.list(LIST_LIMIT);
	}

	@GetMapping("/api/contracts/{nonce}")
	@ResponseBody
	ResponseEntity<?> contractJson(@PathVariable String nonce) {
		Reconciler.Report report = this.reconciler.reconcile(nonce);
		return (report == null) ? ResponseEntity.status(404).body(Map.of("error", "その nonce の契約がない"))
				: ResponseEntity.ok(report);
	}

	private Reconciler.Report found(String nonce) {
		Reconciler.Report report = this.reconciler.reconcile(nonce);
		if (report == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "その nonce の契約がない");
		}
		return report;
	}

}

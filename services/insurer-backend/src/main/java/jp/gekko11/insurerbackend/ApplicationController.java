package jp.gekko11.insurerbackend;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 案の提示、契約の照会、申込みの受付（architecture の 3 章の 2〜6 段）。
 * トークンは token-guard が確かめ、ここは内容だけを確かめる（2-2）。経路の途中のデータは、書き換えられうるものとして扱う。
 * 教材のための意図的に悪い実装を含む。vulnerable の名前空間では、D9、D11〜D18 を外せる。本番の部品として使わないこと。
 */
@RestController
class ApplicationController {

	private static final String CLAIMS = "x-auth-claims";

	private final Store store;

	private final OfferSigner offers;

	private final Seals seals;

	private final Notifier notifier;

	private final Defenses defenses;

	ApplicationController(Store store, OfferSigner offers, Seals seals, Notifier notifier, Defenses defenses) {
		this.store = store;
		this.offers = offers;
		this.seals = seals;
		this.notifier = notifier;
		this.defenses = defenses;
	}

	/** 誰の契約かは、トークンの sub から決める。悪い実装（D9 を外す）は、窓口の言う for_user を信じる。 */
	private String customerOf(Claims claims, String forUser) {
		return (!this.defenses.enabled(Defenses.CUSTOMER_FROM_SUB) && forUser != null) ? forUser : claims.sub();
	}

	@GetMapping("/offers-jwks.json")
	Map<String, Object> jwks() {
		return this.offers.jwks();
	}

	@PostMapping("/offers")
	ResponseEntity<?> offer(@RequestHeader(CLAIMS) String header,
			@RequestBody(required = false) Map<String, Object> body) throws Exception {
		Claims claims = Claims.from(header);
		String customer = customerOf(claims, (body != null) ? (String) body.get("for_user") : null);
		if (!Store.CONTACTS.containsKey(customer)) {
			return ResponseEntity.status(403).body(Map.of("error", "利用者本人のトークンではない"));
		}
		String nonce = UUID.randomUUID().toString();
		long expiresAt = Instant.now().plusSeconds(600).getEpochSecond();
		this.store.nonces.put(nonce, new Store.Nonce(customer, expiresAt, false));
		String jws = this.offers.sign(customer, Store.CATALOG, nonce, expiresAt);
		return ResponseEntity.ok(Map.of("offerJws", jws, "offerSet", Map.of("customer", customer, "plans", Store.CATALOG),
				"offerSetId", OfferSigner.offerSetId(customer, Store.CATALOG), "nonce", nonce, "expiresAt", expiresAt));
	}

	@GetMapping("/contracts")
	ResponseEntity<?> contracts(@RequestHeader(CLAIMS) String header,
			@RequestParam(name = "for_user", required = false) String forUser) {
		String customer = customerOf(Claims.from(header), forUser);
		if (!Store.CONTACTS.containsKey(customer)) {
			return ResponseEntity.status(403).body(Map.of("error", "利用者本人のトークンではない"));
		}
		return ResponseEntity.ok(Map.of("contracts",
				this.store.contracts.stream().map(Store.ContractRecord::contract)
					.filter((c) -> customer.equals(c.get("customer")))
					.toList()));
	}

	@SuppressWarnings("unchecked")
	@PostMapping("/applications")
	ResponseEntity<?> apply(@RequestHeader(CLAIMS) String header, @RequestBody Map<String, Object> body) {
		Claims claims = Claims.from(header);
		Map<String, Object> application = (Map<String, Object>) body.get("application");
		Map<String, Object> intent = (Map<String, Object>) body.get("intent");
		if (application == null || intent == null) {
			return reject("申込みの形", "申込みか意向確認がない", 400);
		}
		Map<String, Object> plan = (Map<String, Object>) application.get("plan");

		// 窓口自身のトークン（sub が顧客でない）を、内部の信頼できる呼び出しとみなす悪い実装がある（D9）
		boolean serviceToken = !this.defenses.enabled(Defenses.CUSTOMER_FROM_SUB)
				&& !Store.CONTACTS.containsKey(claims.sub());
		String customer = serviceToken ? (String) application.get("customer") : claims.sub();
		if (!Store.CONTACTS.containsKey(customer)) {
			return reject("トークンの利用者本人が顧客である", "sub=" + claims.sub() + " は顧客ではない", 403);
		}
		if (!customer.equals(application.get("customer"))) {
			return reject("申込みの契約者がトークンの本人", application.get("customer") + " は " + customer + " ではない", 403);
		}

		// 本人確認が済んでいるか。確認済みの属性は、トークンから取る（D11）
		Map<String, Object> verified = this.defenses.enabled(Defenses.VERIFIED_FROM_TOKEN) ? claims.verifiedClaims()
				: (Map<String, Object>) body.getOrDefault("verified_claims", claims.verifiedClaims());
		if (verified == null || !(verified.get("verification") instanceof Map<?, ?> v) || v.get("method") == null) {
			return reject("本人確認が済んでいる", "確認済みの属性がない", 403);
		}

		// 案が、保険会社の署名つきの提示に含まれるか（D12）
		if (this.defenses.enabled(Defenses.OFFER_SIGNATURE)) {
			try {
				Map<String, Object> offer = this.offers.verify(String.valueOf(body.get("offerJws")));
				if (!customer.equals(offer.get("customer"))) {
					return reject("提示は本人宛て", offer.get("customer") + " 宛ての提示", 403);
				}
				if (!Objects.equals(offer.get("offerSetId"), application.get("offerSetId"))
						|| !Objects.equals(offer.get("nonce"), application.get("nonce"))) {
					return reject("申込みが提示と対応", "提示集合の識別子か nonce が違う", 403);
				}
				String chosen = Canonical.of(plan);
				if (((List<Object>) offer.get("plans")).stream().noneMatch((p) -> Canonical.of(p).equals(chosen))) {
					return reject("案が提示に含まれる", "提示にない案", 403);
				}
			}
			catch (Exception ex) {
				return reject("提示の署名が有効", ex.getMessage(), 403);
			}
		}

		// 申込みの内容が、署名したときのままか（D13）
		Seals.Result seal = this.defenses.variant(Defenses.PASSKEY_SEAL)
			.map((how) -> switch (how) {
				case "mtls-only" -> this.seals.mtlsOnly(claims.peer());
				case "agent-signed" -> this.seals.agentSigned(application, body.get("assertion"));
				default -> new Seals.Result(true, "署名を確かめていない");
			})
			.orElseGet(() -> this.seals.passkey(application, body.get("assertion"), customer));
		if (!seal.ok()) {
			return reject("申込みの署名の照合", seal.detail(), 403);
		}

		// 意向確認と申込みの署名の連鎖（D14）
		if (this.defenses.enabled(Defenses.SEAL_CHAIN)) {
			Seals.Result intentSeal = this.seals.passkey(intent, body.get("intentAssertion"), customer);
			if (!intentSeal.ok()) {
				return reject("意向確認の署名", intentSeal.detail(), 403);
			}
			Object intentSignature = (body.get("intentAssertion") instanceof Map<?, ?> ia
					&& ia.get("response") instanceof Map<?, ?> r) ? r.get("signature") : null;
			boolean same = customer.equals(intent.get("customer"))
					&& Objects.equals(intent.get("offerSetId"), application.get("offerSetId"))
					&& Objects.equals(intent.get("planId"), plan.get("id"))
					&& Objects.equals(intent.get("nonce"), application.get("nonce"))
					&& Objects.equals(intentSignature, application.get("intentSignature"));
			if (!same) {
				return reject("意向確認と申込みが対応", "申込みが、署名した意向確認とつながっていない", 403);
			}
		}

		// 取決め（扱える保険の種類、年金の年額の上限）との照合（D15）
		if (!serviceToken && this.defenses.enabled(Defenses.TERMS_RANGE)) {
			if (!claims.hasScope("apply")) {
				return reject("取決め（scope）", "apply が許されていない", 403);
			}
			Map<String, Object> terms = claims.terms();
			if (terms == null) {
				return reject("取決め（RAR）", "取決めがない", 403);
			}
			if (!((List<Object>) terms.getOrDefault("kinds", List.of())).contains(plan.get("kind"))) {
				return reject("扱える保険の種類", plan.get("kind") + " は取決めの範囲外", 403);
			}
			if (((Number) plan.get("benefit")).longValue() > ((Number) terms.get("maxBenefit")).longValue()) {
				return reject("年金の年額の上限以内", plan.get("benefit") + " 円は上限を超えている", 403);
			}
		}

		// 一度しか受け付けない（D16）
		String nonceValue = String.valueOf(application.get("nonce"));
		Store.Nonce nonce = this.store.nonces.get(nonceValue);
		long now = Instant.now().getEpochSecond();
		if (this.defenses.enabled(Defenses.NONCE_ONCE) && (nonce == null || nonce.used()
				|| !customer.equals(nonce.customer()) || nonce.expiresAt() < now
				|| ((Number) application.get("expiresAt")).longValue() < now)) {
			return reject("申込みは未使用で期限内", "使用済み、期限切れ、または発行していない nonce", 409);
		}
		if (nonce != null) {
			this.store.nonces.put(nonceValue, new Store.Nonce(nonce.customer(), nonce.expiresAt(), true));
		}

		// 契約の記録は、署名済みの申込みから導出する。悪い実装（D17 を外す）は、入力された内容を信じる
		Map<String, Object> contract = derive(application);
		if (!this.defenses.enabled(Defenses.DERIVE_RECORD) && body.get("contractEntry") instanceof Map<?, ?> entry) {
			contract.putAll((Map<String, Object>) entry);
		}
		this.store.contracts
			.add(new Store.ContractRecord(contract, claims.actChain(), now, application, intent));

		// 顧客へ直接送る。宛先は、登録済みの連絡先（D18）
		String to = (!this.defenses.enabled(Defenses.REGISTERED_CONTACT) && body.get("contact") instanceof String c) ? c
				: Store.CONTACTS.get(customer);
		this.notifier.send(to, Map.of("customer", customer, "contract", contract));
		return ResponseEntity.ok(Map.of("ok", true, "contract", contract));
	}

	/** 契約の記録。人も AI も入力し直さず、署名済みの申込みから決まった規則で作る（P-16）。 */
	static Map<String, Object> derive(Map<String, Object> application) {
		Map<String, Object> contract = new LinkedHashMap<>();
		contract.put("contractId", "C-" + Canonical.challengeOf(application).substring(0, 12));
		contract.put("customer", application.get("customer"));
		contract.put("plan", application.get("plan"));
		contract.put("offerSetId", application.get("offerSetId"));
		contract.put("nonce", application.get("nonce"));
		return contract;
	}

	private static ResponseEntity<?> reject(String check, String detail, int status) {
		return ResponseEntity.status(status).body(Map.of("error", check + ": " + detail));
	}

}

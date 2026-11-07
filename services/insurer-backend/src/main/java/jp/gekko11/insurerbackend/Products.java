package jp.gekko11.insurerbackend;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 商品の規則と計算（教材用の仮の値で、実在の料率ではない。implementation の 5 章）。
 * 営業 AI エージェントは、掛け金を変えて試算を頼み、希望に近い案を探す。計算は、ここだけが行う（P-17）。
 */
final class Products {

	private static final Set<Long> FIXED_TERMS = Set.of(5L, 10L, 15L, 20L);

	private static final long DEFAULT_TERM = 10;

	private static final long DEFAULT_PAY = 25;

	private static final long MIN_PAY = 10;

	private static final long MAX_PAY = 35;

	private static final long MONTHLY_STEP = 1_000;

	private static final long BENEFIT_STEP = 10_000;

	private static final long MIN_BENEFIT = 120_000;

	private static final long MAX_BENEFIT = 3_600_000;

	/** 終身年金の年額を計算するときに、受取期間として見なす年数。 */
	private static final long LIFETIME_YEARS = 15;

	private Products() {
	}

	/** 試算の結果。案か、断る理由のどちらかを持つ。 */
	record Result(Map<String, Object> plan, String reason) {
	}

	/** 営業 AI エージェントに公開する規則。 */
	static Map<String, Object> rules() {
		return Map.of("products", List.of(
				Map.of("kind", "fixed", "name", "確定年金", "termYears", List.of(5, 10, 15, 20)),
				Map.of("kind", "lifetime", "name", "終身年金")),
				"monthlyStepYen", MONTHLY_STEP, "payYears", Map.of("min", MIN_PAY, "max", MAX_PAY, "default", DEFAULT_PAY),
				"annualPensionYen", Map.of("min", MIN_BENEFIT, "max", MAX_BENEFIT),
				"note", "月額の保険料と払込期間から、年金の年額を計算する。年金の年額から保険料は計算しない");
	}

	/** 条件（商品、受取期間、払込期間、月額の保険料）から、規則を確かめて案を計算する。 */
	static Result quote(Map<String, Object> condition) {
		String kind = String.valueOf(condition.get("kind"));
		if (!kind.equals("fixed") && !kind.equals("lifetime")) {
			return refuse("扱う商品は、確定年金（fixed）と終身年金（lifetime）だけである");
		}
		Long term = number(condition.get("termYears"));
		Long pay = number(condition.getOrDefault("payYears", DEFAULT_PAY));
		Long monthly = number(condition.get("monthly"));
		if (kind.equals("fixed") && condition.get("termYears") != null && (term == null || !FIXED_TERMS.contains(term))) {
			return refuse("確定年金の受取期間は、5、10、15、20 年である");
		}
		if (kind.equals("lifetime") && condition.get("termYears") != null) {
			return refuse("終身年金に受取期間はない");
		}
		if (pay == null || pay < MIN_PAY || pay > MAX_PAY) {
			return refuse("払込期間は、" + MIN_PAY + "〜" + MAX_PAY + " 年である");
		}
		if (monthly == null || monthly <= 0 || monthly % MONTHLY_STEP != 0) {
			return refuse("月額の保険料は、" + MONTHLY_STEP + " 円刻みである");
		}
		long years = kind.equals("lifetime") ? LIFETIME_YEARS : (term != null) ? term : DEFAULT_TERM;
		long benefit = monthly * 12 * pay / years / BENEFIT_STEP * BENEFIT_STEP;
		if (benefit < MIN_BENEFIT || benefit > MAX_BENEFIT) {
			return refuse("年金の年額（計算で " + benefit + " 円）は、" + MIN_BENEFIT + "〜" + MAX_BENEFIT + " 円の範囲である");
		}
		return new Result(plan(kind, years, pay, benefit, monthly), null);
	}

	/** 提出された案が、規則に合い、金額が計算と一致するか。合わないときは理由を返す。黙って直さない。 */
	static String verify(Map<String, Object> submitted) {
		Result result = quote(submitted);
		if (result.reason() != null) {
			return result.reason();
		}
		Long benefit = number(submitted.get("benefit"));
		if (benefit == null || benefit.longValue() != ((Number) result.plan().get("benefit")).longValue()) {
			return "年金の年額が計算と違う（提出 " + submitted.get("benefit") + " 円、計算 " + result.plan().get("benefit") + " 円）";
		}
		return null;
	}

	/** 提出された値のまま案にする。D30 を外した悪い実装だけが使う。本番の部品として使わないこと。 */
	static Map<String, Object> unchecked(Map<String, Object> submitted) {
		String kind = String.valueOf(submitted.get("kind"));
		Long term = number(submitted.getOrDefault("termYears", DEFAULT_TERM));
		Long pay = number(submitted.getOrDefault("payYears", DEFAULT_PAY));
		Long benefit = number(submitted.get("benefit"));
		Long monthly = number(submitted.get("monthly"));
		return plan(kind, (term != null) ? term : DEFAULT_TERM, (pay != null) ? pay : DEFAULT_PAY,
				(benefit != null) ? benefit : 0, (monthly != null) ? monthly : 0);
	}

	/** 案の 5 つの欄。受取期間と払込期間は、既定と違うときだけ、番号と名前に入れる。 */
	static Map<String, Object> plan(String kind, long years, long pay, long benefit, long monthly) {
		boolean fixed = kind.equals("fixed");
		String man = String.valueOf(benefit / 10_000);
		String id = (fixed ? "fixed" : "life") + ((fixed && years != DEFAULT_TERM) ? "-" + years + "y" : "") + "-" + man
				+ ((pay != DEFAULT_PAY) ? "-" + pay + "p" : "");
		String name = (fixed ? "確定年金 " + years + "年" : "終身年金") + "・年額" + man + "万円"
				+ ((pay != DEFAULT_PAY) ? "・払込" + pay + "年" : "");
		Map<String, Object> plan = new LinkedHashMap<>();
		plan.put("id", id);
		plan.put("name", name);
		plan.put("kind", kind);
		plan.put("benefit", benefit);
		plan.put("monthly", monthly);
		return plan;
	}

	private static Result refuse(String reason) {
		return new Result(null, reason);
	}

	private static Long number(Object value) {
		return (value instanceof Number n && n.doubleValue() == n.longValue()) ? Long.valueOf(n.longValue()) : null;
	}

}

package jp.gekko11.insurerauth;

import java.util.Map;

/** 誰に、どの宛先のトークンを出すか（architecture の 4-4、D-7）。 */
final class ExchangePolicy {

	static final String CUSTOMER_APP = "customer-app";

	static final String SALES_AGENT = "sales-agent";

	static final String INSURER_MCP = "insurer-mcp";

	static final String INSURER_BACKEND = "insurer-backend";

	/** 顧客のアプリが受け取るトークン A の宛先。 */
	static final String CUSTOMER_AUDIENCE = SALES_AGENT;

	/** 替えを頼む窓口ごとに、替えてよい宛先。 */
	private static final Map<String, String> NEXT = Map.of(SALES_AGENT, INSURER_MCP, INSURER_MCP, INSURER_BACKEND);

	private ExchangePolicy() {
	}

	static boolean mayExchangeTo(String requester, String audience) {
		return audience.equals(NEXT.get(requester));
	}

	/** 宛先のサービスが、そのトークンを替えてよい（may_act を付ける）か。 */
	static boolean exchanges(String audience) {
		return NEXT.containsKey(audience);
	}

}

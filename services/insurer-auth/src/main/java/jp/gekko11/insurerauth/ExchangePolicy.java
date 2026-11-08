package jp.gekko11.insurerauth;

import java.util.Map;

/** 誰に、どの宛先のトークンを出すか（architecture の 4-4、D-7）。 */
final class ExchangePolicy {

	static final String CUSTOMER_APP = "customer-app";

	static final String SALES_AGENT = "sales-agent";

	static final String INSURER_MCP = "insurer-mcp";

	static final String INSURER_BACKEND = "insurer-backend";

	/** 認可サーバー自身。受信箱の番号の登録と passkey の一覧の読み取りに使う P の宛先（D-42、D-43）。 */
	static final String INSURER_AUTH = "insurer-auth";

	/** 替えを頼む窓口ごとに、替えてよい宛先。 */
	private static final Map<String, String> NEXT = Map.of(SALES_AGENT, INSURER_MCP, INSURER_MCP, INSURER_BACKEND);

	/** トークンの宛先になりうるサービス。 */
	static final java.util.List<String> SERVICES = java.util.List.of(SALES_AGENT, INSURER_MCP, INSURER_BACKEND);

	private ExchangePolicy() {
	}

	/** 替えを頼む窓口が、次に呼ぶ宛先。 */
	static String next(String requester) {
		return NEXT.get(requester);
	}

	static boolean mayExchangeTo(String requester, String audience) {
		return audience.equals(NEXT.get(requester));
	}

	/** 宛先のサービスが、そのトークンを替えてよい（may_act を付ける）か。 */
	static boolean exchanges(String audience) {
		return NEXT.containsKey(audience);
	}

}

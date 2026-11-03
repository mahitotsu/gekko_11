package jp.gekko11.insureraudit;

import java.util.List;
import java.util.Map;

/** 突き合わせに使う記録の出どころ。クラスタでは Loki と保険会社のシステムで、単体テストではメモリ上の記録である。 */
interface RecordSource {

	/** その文字列（nonce、jti、会話の識別子）を含む監査の記録。書いた者を問わずに返し、確かめは突き合わせが行う。 */
	List<AuditEntry> search(String needle);

	/** 契約の記録（kind が contract）。一覧の画面に使う。 */
	List<AuditEntry> contracts();

	/** 保険会社のシステムの自己申告（/audit/records の契約）。 */
	List<Map<String, Object>> selfReported();

}

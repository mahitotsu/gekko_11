package jp.gekko11.insureraudit;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/** 監査の画面の見出しに、名前空間を出す。防御を外せる複製（vulnerable）の記録を見ていると分かるようにする。 */
@ControllerAdvice(assignableTypes = AuditController.class)
class PageAttributes {

	private final AuditProperties props;

	PageAttributes(AuditProperties props) {
		this.props = props;
	}

	@ModelAttribute("namespace")
	String namespace() {
		return this.props.namespace();
	}

}

package jp.gekko11.insurerlogin;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oidc.rar.InvalidAuthorizationDetailsException;
import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;

/** 取決めの範囲の形の確かめ（D-39）。契約の種類と上限がそろえば通し、欠ければ断る。 */
class InsuranceTermsProcessorTest {

	private final InsuranceTermsProcessor processor = new InsuranceTermsProcessor();

	private static AuthorizationDetailsJSONRepresentation terms(Object kinds, Object maxBenefit) {
		AuthorizationDetailsJSONRepresentation detail = new AuthorizationDetailsJSONRepresentation();
		detail.setType(InsuranceTermsProcessor.TYPE);
		if (kinds != null) {
			detail.setCustomData("kinds", kinds);
		}
		if (maxBenefit != null) {
			detail.setCustomData("maxBenefit", maxBenefit);
		}
		return detail;
	}

	@Test
	void termsWithKindsAndUpperLimitPass() throws Exception {
		AuthorizationDetailsJSONRepresentation detail = terms(List.of("fixed"), 600_000);
		assertSame(detail, this.processor.validateAuthorizationDetail(detail));
	}

	@Test
	void termsWithoutKindsAreRefused() {
		assertThrows(InvalidAuthorizationDetailsException.class,
				() -> this.processor.validateAuthorizationDetail(terms(null, 600_000)));
	}

	@Test
	void termsWithoutANumericUpperLimitAreRefused() {
		assertThrows(InvalidAuthorizationDetailsException.class,
				() -> this.processor.validateAuthorizationDetail(terms(List.of("fixed"), null)));
		assertThrows(InvalidAuthorizationDetailsException.class,
				() -> this.processor.validateAuthorizationDetail(terms(List.of("fixed"), "600000")));
	}

}

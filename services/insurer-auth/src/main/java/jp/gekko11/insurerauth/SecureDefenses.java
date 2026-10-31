package jp.gekko11.insurerauth;

import org.springframework.stereotype.Component;

/** secure の版。防御を外す受け口を持たない。 */
@Component
class SecureDefenses implements Defenses {

	@Override
	public boolean enabled(String id) {
		return true;
	}

}

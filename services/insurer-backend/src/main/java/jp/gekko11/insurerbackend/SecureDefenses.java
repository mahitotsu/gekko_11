package jp.gekko11.insurerbackend;

import java.util.Optional;

import org.springframework.stereotype.Component;

/** secure の版。防御を外す受け口を持たない。 */
@Component
class SecureDefenses implements Defenses {

	@Override
	public boolean enabled(String id) {
		return true;
	}

	@Override
	public Optional<String> variant(String id) {
		return Optional.empty();
	}

}

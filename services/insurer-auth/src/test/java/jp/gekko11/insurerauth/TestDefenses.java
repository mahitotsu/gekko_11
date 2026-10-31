package jp.gekko11.insurerauth;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** テストで、防御を外す。vulnerable の版と同じく、外した ID だけが無効になる。 */
@TestConfiguration
class TestDefenses {

	static final Set<String> OFF = ConcurrentHashMap.newKeySet();

	@Bean
	@Primary
	Defenses testDefenses() {
		return (id) -> !OFF.contains(id);
	}

}

package jp.gekko11.insurerauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** 認可サーバー（insurer-auth）。トークンを出し、替える（architecture の 2 章、D-19）。 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class InsurerAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(InsurerAuthApplication.class, args);
	}

}

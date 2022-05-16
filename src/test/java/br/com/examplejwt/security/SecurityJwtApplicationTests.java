package br.com.examplejwt.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class SecurityJwtApplicationTests {

	private static final String API = "Api";

	@Test
	void contextLoads() {
		assertEquals("Api", API);
	}

}

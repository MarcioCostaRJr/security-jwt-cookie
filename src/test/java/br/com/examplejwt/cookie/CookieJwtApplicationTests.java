package br.com.examplejwt.cookie;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class CookieJwtApplicationTests {

	private static final String API = "Api";

	@Test
	void contextLoads() {
		assertEquals("Api", API);
	}

}

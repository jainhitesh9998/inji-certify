package io.mosip.certify;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The application context starts with the local and test profiles. It used to boot a second application through
 * {@code CertifyServiceApplication.main()} inside the test context, which bound port 8090 and shared the keystore
 * with every other test context in the JVM (R-02).
 */
@SpringBootTest
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
class CertifyApplicationTests {

    @Autowired
    ApplicationContext context;

    @Test
    void contextLoads() {
        assertNotNull(context);
        assertTrue(context.containsBean("certifyServiceApplication"), "the application class is the root of the context");
    }
}

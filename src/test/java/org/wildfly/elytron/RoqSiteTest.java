package org.wildfly.elytron;

import io.quarkiverse.roq.testing.RoqAndRoll;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

@QuarkusTest
@RoqAndRoll
public class RoqSiteTest {
    @Test
    public void testGen() {
        // All pages will be generated/validated during test setup
    }
}

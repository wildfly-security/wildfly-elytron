/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.test;

import static java.util.Collections.emptyMap;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Test;

/**
 * Black-box testing of SASL factories implementations.
 *
 * @author Josef Cacek
 */
public class SaslFactoriesApiTest extends BaseTestCase {

    private static final String REGEX_MECHANISM_NAME = "^[A-Z0-9-_]{1,20}$";

    /**
     * Tests behavior of {@link SaslClientFactory#getMechanismNames(java.util.Map)}. The contract says that {@code props}
     * parameter can be null and that the method returns not-{@code null} object.
     */
    @Test
    public void testSaslClientFactoryGetMechanismNamesNotNull() {
        Collections.list(Sasl.getSaslClientFactories()).forEach(cf -> {
            assertNotNull(cf.getMechanismNames(null));
            assertNotNull(cf.getMechanismNames(emptyMap()));
        });
    }

    /**
     * Tests that the mechanism names retrieved from {@link SaslClientFactory#getMechanismNames(java.util.Map)} fits
     * <a href="https://tools.ietf.org/html/rfc4422#section-3.1">SASL mechanism naming</a> requirements.
     */
    @Test
    public void testSaslClientFactoryGetMechanismNamesValid() {
        Collections.list(Sasl.getSaslClientFactories()).stream().flatMap(cf -> Arrays.stream(cf.getMechanismNames(emptyMap())))
                .forEach(s -> assertThat(s, RegularExpressionMatcher.matchesPattern(REGEX_MECHANISM_NAME)));
    }

    /**
     * Tests that {@link SaslClientFactory#createSaslClient(String[], String, String, String, Map, CallbackHandler)} correctly
     * handles null parameters as required by the method contract. Returned {@code null} value or the {@link SaslException}
     * thrown during the call are correct states.
     */
    @Test
    public void testCreateSaslClientNullParams() {
        Collections.list(Sasl.getSaslClientFactories()).forEach(cf -> {
            Arrays.stream(cf.getMechanismNames(emptyMap())).forEach(mech -> {
                try {
                    SaslClient sc = cf.createSaslClient(new String[] { mech }, null, "test", "localhost", null, null);
                    if (sc != null) {
                        sc.dispose();
                    }
                } catch (SaslException | IllegalArgumentException e) {
                    // OK - a correct error state
                }
            });
        });
    }

    /**
     * Tests behavior of {@link SaslServerFactory#getMechanismNames(java.util.Map)}. The contract says that {@code props}
     * parameter can be null and that the method returns not-{@code null} object.
     */
    @Test
    public void testSaslServerFactoryGetMechanismNamesNotNull() {
        Collections.list(Sasl.getSaslServerFactories()).forEach(sf -> {
            assertNotNull(sf.getMechanismNames(null));
            assertNotNull(sf.getMechanismNames(emptyMap()));
        });
    }

    /**
     * Tests that the mechanism names retrieved from {@link SaslServerFactory#getMechanismNames(java.util.Map)} fits
     * <a href="https://tools.ietf.org/html/rfc4422#section-3.1">SASL mechanism naming</a> requirements.
     */
    @Test
    public void testSaslServerFactoryGetMechanismNamesValid() {
        Collections.list(Sasl.getSaslClientFactories()).stream().flatMap(sf -> Arrays.stream(sf.getMechanismNames(emptyMap())))
                .forEach(s -> assertThat(s, RegularExpressionMatcher.matchesPattern(REGEX_MECHANISM_NAME)));
    }

    /**
     * Tests that {@link SaslServerFactory#createSaslServer(String, String, String, Map, CallbackHandler)} correctly handles
     * null parameters as required by the method contract. Returned {@code null} value or the {@link SaslException} thrown
     * during the call are correct states.
     */
    @Test
    public void testCreateSaslServerNullParams() {
        Collections.list(Sasl.getSaslServerFactories()).forEach(sf -> {
            Arrays.stream(sf.getMechanismNames(emptyMap())).forEach(mech -> {
                try {
                    SaslServer ss = sf.createSaslServer(mech, "test", null, null, null);
                    if (ss != null) {
                        ss.dispose();
                    }
                } catch (SaslException | IllegalArgumentException e) {
                    // OK - a correct error state
                }
            });
        });
    }

    private static class RegularExpressionMatcher extends TypeSafeMatcher<String> {

        private final Pattern pattern;

        public RegularExpressionMatcher(String regExp) {
            this.pattern = Pattern.compile(Objects.requireNonNull(regExp));
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("matches regular expression ").appendValue(pattern);
        }

        @Override
        public boolean matchesSafely(String item) {
            return pattern.matcher(item).matches();
        }

        @Factory
        public static Matcher<String> matchesPattern(String pattern) {
            return new RegularExpressionMatcher(pattern);
        }
    }
}

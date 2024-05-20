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

package org.wildfly.security.ssl;

import java.util.Arrays;
import java.util.List;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Tests evaluation of {@link CipherSuiteSelector} from string.
 *
 * @author Ondrej Kotek <okotek@redhat.com>
 */
public class CipherSuiteSelectorTest {

    private static final String[] SUPPORTED_SUITES = new String[] {
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_NULL_SHA256",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_anon_WITH_NULL_SHA",
        "TLS_AES_128_GCM_SHA256", // TLS 1.3
        "TLS_CHACHA20_POLY1305_SHA256", // TLS 1.3
        "TLS_AES_128_CCM_SHA256", // TLS 1.3
        "TLS_AES_128_CCM_8_SHA256"}; // TLS 1.3

    private List<String> getSelectedSuites(String cipherList, String[] supportedSuites, boolean isTLSv1_3) {
        if (isTLSv1_3)
            return Arrays.asList(CipherSuiteSelector.fromNamesString(cipherList).evaluate(supportedSuites));
        else
            return Arrays.asList(CipherSuiteSelector.fromString(cipherList).evaluate(supportedSuites));
    }

    @Test
    public void testAll() {
        List<String> selectedSuites = getSelectedSuites("ALL", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, not(hasItem("TLS_RSA_WITH_NULL_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_ECDH_anon_WITH_NULL_SHA")));
        assertThat(selectedSuites, not(hasItem("TLS_AES_128_GCM_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_CHACHA20_POLY1305_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_AES_128_CCM_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_AES_128_CCM_8_SHA256")));
        assertThat("Suites with encryption should be selected", selectedSuites.size() == SUPPORTED_SUITES.length - 6);
    }

    @Test
    public void testComplementofall() {
        List<String> selectedSuites = getSelectedSuites("COMPLEMENTOFALL", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_NULL_SHA256", "TLS_ECDH_anon_WITH_NULL_SHA"));
        assertThat("Suites without encryption should be selected", selectedSuites.size() == 2);
    }

    @Test
    public void testDefault() {
        List<String> selectedSuites = getSelectedSuites("DEFAULT", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_RSA_WITH_AES_128_CBC_SHA256"));
        assertThat("Suites with encryption and authentication should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testComplementofdefault() {
        List<String> selectedSuites = getSelectedSuites("COMPLEMENTOFDEFAULT", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("Suites with encryption without authentication should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testSingleSuiteUsingStandardName() {
        List<String> selectedSuites = getSelectedSuites("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA", new String[] {"SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA"}, false);

        assertThat(selectedSuites, hasItem("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
        assertThat("The only suite should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testSingleSuiteUsingOpensslName() {
        List<String> selectedSuites = getSelectedSuites("ECDHE-RSA-AES128-SHA", new String[] {"SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA"}, false);

        assertThat(selectedSuites, hasItem("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
        assertThat("The only suite should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testSingleTlsSuiteUsingSslPrefixName() {
        List<String> selectedSuites = getSelectedSuites("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", new String[] {"TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"}, false);

        assertThat(selectedSuites, hasItem("TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"));
        assertThat("The only suite should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testPlusBetweenAnonAndNullEncryption() {
        List<String> selectedSuites = getSelectedSuites("aNULL+eNULL", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_ECDH_anon_WITH_NULL_SHA"));
        assertThat("Suites without both encryption and authenticaiton should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testPlusBetweenAnonAndTls12() {
        List<String> selectedSuites = getSelectedSuites("aNULL+TLSv1.2", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("TLSv1.2 suites without authenticaiton should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testDoublePlusBetweenAnonAndTls12() {
        List<String> selectedSuites = getSelectedSuites("aNULL++TLSv1.2", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("TLSv1.2 suites without authenticaiton should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testPlusBetweenAnonAndTls12AndAfter() {
        List<String> selectedSuites = getSelectedSuites("aNULL+TLSv1.2+", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("TLSv1.2 suites without authenticaiton should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testMultiplePlus() {
        List<String> selectedSuites = getSelectedSuites("aRSA+kRSA+AES+TLSv1.2", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_RSA_WITH_AES_128_CBC_SHA256"));
        assertThat("TLSv1.2 RSA suites using AES should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testPlusBeforeFirstRsa() {
        List<String> selectedSuites = getSelectedSuites("RSA +AES", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256"));
        assertThat("RSA suites should be selected", selectedSuites.size() == 2);
        assertThat("The last selected suite uses AES", selectedSuites.get(1), is("TLS_RSA_WITH_AES_128_CBC_SHA256"));
    }

    @Test
    public void testMinusAesAfterRsa() {
        List<String> selectedSuites = getSelectedSuites("RSA -AES", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_RSA_WITH_NULL_SHA256"));
        assertThat("RSA suites not using AES should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testMinusBetweenRsaAndAes() {
        List<String> selectedSuites = getSelectedSuites("RSA - AES", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256", "TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("RSA suites not using AES should be selected", selectedSuites.size() == 3);
    }

    @Test
    public void testMinusAesBetweenRsaAndAes() {
        List<String> selectedSuites = getSelectedSuites("RSA -AES AES", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256", "TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("RSA suites and suites using AES should be selected", selectedSuites.size() == 3);
    }

    @Test
    public void testMinusRsaBetweenRsaAndRsa() {
        List<String> selectedSuites = getSelectedSuites("RSA -RSA RSA", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256"));
        assertThat("RSA suites should be selected", selectedSuites.size() == 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMinusBetweenRsaAes() {
        CipherSuiteSelector.fromString("RSA-AES");
    }

    @Test
    public void testNotRsaAfterRsa() {
        List<String> selectedSuites = getSelectedSuites("RSA !RSA", SUPPORTED_SUITES, false);

        assertThat("No suites should be selected", selectedSuites.isEmpty());
    }

    @Test
    public void testNotRsaBetweenRsaAndRsa() {
        List<String> selectedSuites = getSelectedSuites("RSA !RSA RSA", SUPPORTED_SUITES, false);

        assertThat("No suites should be selected", selectedSuites.isEmpty());
    }

    @Test
    public void testNotAesBetweenRsaAndAes() {
        List<String> selectedSuites = getSelectedSuites("RSA !AES AES", SUPPORTED_SUITES, false);

        assertThat(selectedSuites, hasItem("TLS_RSA_WITH_NULL_SHA256"));
        assertThat("RSA suites not using AES should be selected", selectedSuites.size() == 1);
    }

    @Test
    public void testStrengthForAllAndComplementofall() {
        List<String> selectedSuites = getSelectedSuites("ALL COMPLEMENTOFALL @STRENGTH", SUPPORTED_SUITES, false);

        assertThat("All pre TLS 1.3 supported suites should be selected", selectedSuites.size() == 4);
        assertThat("High strength suites should be at the beginning", selectedSuites.get(0), is("TLS_RSA_WITH_AES_128_CBC_SHA256"));
        assertThat("High strength suites should be at the beginning", selectedSuites.get(1), is("TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("Low strength suites should be at the end", selectedSuites.get(2), is("TLS_RSA_WITH_NULL_SHA256"));
        assertThat("Low strength suites should be at the end", selectedSuites.get(3), is("TLS_ECDH_anon_WITH_NULL_SHA"));
    }

    @Test
    public void testStrengthForComplementofallAndAll() {
        List<String> selectedSuites = getSelectedSuites("COMPLEMENTOFALL ALL @STRENGTH", SUPPORTED_SUITES, false);

        assertThat("All pre TLS 1.3 supported suites should be selected", selectedSuites.size() == 4);
        assertThat("High strength suites should be at the beginning", selectedSuites.get(0), is("TLS_RSA_WITH_AES_128_CBC_SHA256"));
        assertThat("High strength suites should be at the beginning", selectedSuites.get(1), is("TLS_DH_anon_WITH_AES_128_CBC_SHA256"));
        assertThat("Low strength suites should be at the end", selectedSuites.get(2), is("TLS_RSA_WITH_NULL_SHA256"));
        assertThat("Low strength suites should be at the end", selectedSuites.get(3), is("TLS_ECDH_anon_WITH_NULL_SHA"));
    }

    @Test
    public void testSeparatorSpace() {
        List<String> selectedSuites = getSelectedSuites("TLS_RSA_WITH_AES_128_CBC_SHA256 TLS_RSA_WITH_NULL_SHA256", SUPPORTED_SUITES, false);

        assertThat("Chosen suites should be selected", selectedSuites.size() == 2);
        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256"));
    }

    @Test
    public void testSeparatorComma() {
        List<String> selectedSuites = getSelectedSuites("TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_NULL_SHA256", SUPPORTED_SUITES, false);

        assertThat("Chosen suites should be selected", selectedSuites.size() == 2);
        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256"));
    }

    @Test
    public void testSeparatorColon() {
        List<String> selectedSuites = getSelectedSuites("TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_RSA_WITH_NULL_SHA256", SUPPORTED_SUITES, false);

        assertThat("Chosen suites should be selected", selectedSuites.size() == 2);
        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256"));
    }

    @Test
    public void testSeparatorCommaSpace() {
        List<String> selectedSuites = getSelectedSuites("TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_NULL_SHA256", SUPPORTED_SUITES, false);

        assertThat("Chosen suites should be selected", selectedSuites.size() == 2);
        assertThat(selectedSuites, hasItems("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_NULL_SHA256"));
    }

    @Test
    public void testTLS13NameInCipherList() {
        try {
            CipherSuiteSelector.fromString("TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_AES_128_CCM_8_SHA256");
            fail("Expected IllegalArgumentException not thrown");
        } catch (Exception expected) {
        }
    }

    // TLS 1.3 tests

    @Test
    public void testValidCipherSuites() {
        List<String> selectedSuites = getSelectedSuites("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_CCM_SHA256", SUPPORTED_SUITES, true);

        assertThat("TLS_AES_256_GCM_SHA384 should not be selected", selectedSuites.size() == 3);
        assertThat(selectedSuites, hasItems("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_8_SHA256", "TLS_AES_128_CCM_SHA256"));
    }

    @Test
    public void testTLS12NameInCipherSuites() {
        try {
            CipherSuiteSelector.fromNamesString("TLS_CHACHA20_POLY1305_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256");
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testInvalidFormatCipherSuites() {
        try {
            CipherSuiteSelector.fromNamesString("TLS_CHACHA20_POLY1305_SHA256 !TLS_AES_128_CCM_8_SHA256");
            fail("Expected IllegalArgumentException not thrown");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testCombinedDefaultCipherSuites() {
        CipherSuiteSelector selector = CipherSuiteSelector.openSslCombinedDefault();
        List<String> selectedSuites = Arrays.asList(selector.evaluate(SUPPORTED_SUITES));
        assertThat(selectedSuites, not(hasItem("TLS_RSA_WITH_NULL_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_DH_anon_WITH_AES_128_CBC_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_ECDH_anon_WITH_NULL_SHA")));
        assertThat(selectedSuites, not(hasItem("TLS_AES_128_CCM_SHA256")));
        assertThat(selectedSuites, not(hasItem("TLS_AES_128_CCM_8_SHA256")));
        assertThat("Only default pre TLS 1.3 and default TLS 1.3 cipher suites should be selected", selectedSuites.size() == SUPPORTED_SUITES.length - 5);
    }

}

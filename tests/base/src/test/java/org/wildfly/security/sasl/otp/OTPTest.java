/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.otp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_MD5;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA1;
import static org.wildfly.security.sasl.otp.OTP.DIRECT_OTP;
import static org.wildfly.security.sasl.otp.OTP.HEX_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.INIT_HEX_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.INIT_WORD_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.MATCH_NEW_PASSWORD_FORMAT_CHOICE;
import static org.wildfly.security.sasl.otp.OTP.MATCH_PASSWORD_FORMAT_CHOICE;
import static org.wildfly.security.sasl.otp.OTP.MATCH_RESPONSE_CHOICE;
import static org.wildfly.security.sasl.otp.OTP.PASS_PHRASE;
import static org.wildfly.security.sasl.otp.OTP.WORD_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.getOTPParameterSpec;
import static org.wildfly.security.sasl.test.SaslTestUtil.obtainSaslClientFactory;
import static org.wildfly.security.sasl.test.SaslTestUtil.obtainSaslServerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.PasswordResetCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.CallbackKind;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.test.SaslServerBuilder.BuilderReference;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

/**
 * Client and server side tests for the OTP SASL mechanism. The expected results for
 * these test cases were generated using the {@code python-otp} module.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
// has dependency on wildfly-elytron-client
@RunWith(JMockit.class)
public class OTPTest {

    private long timeout;

    private static final Provider provider = WildFlyElytronSaslOTPProvider.getInstance();

    @BeforeClass
    public static void registerPasswordProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removePasswordProvider() {
        Security.removeProvider(provider.getName());
    }

    @After
    public void dispose() throws Exception {
        timeout = 0L;
    }


    // -- Successful authentication exchanges --

    @Test
    public void testSimpleMD5AuthenticationWithPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;

        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234", 499));

        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, HEX_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("hex:5bf075d9959d036f", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testSimpleSHA1AuthenticationWithPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt", 100));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("87fec7768b73ccf9").hexDecode().drain(),
                "TeSt", 99));

        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, HEX_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-sha1 99 TeSt ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("hex:87fec7768b73ccf9", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testSimpleMD5AuthenticationWithMultiWordOTP() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "BOND FOGY DRAB NE RISE MART", DIRECT_OTP, algorithm, WORD_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:BOND FOGY DRAB NE RISE MART", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testSimpleSHA1AuthenticationWithMultiWordOTP() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt", 100));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("87fec7768b73ccf9").hexDecode().drain(),
                "TeSt", 99));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "GAFF WAIT SKID GIG SKY EYED", DIRECT_OTP, algorithm, WORD_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-sha1 99 TeSt ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:GAFF WAIT SKID GIG SKY EYED", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Ignore("ELY-777")
    @Test
    public void testAuthenticationWithInitHexResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("3712dcb4aa5316c1").hexDecode().drain(),
                "ke1235", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, INIT_HEX_RESPONSE, "3712dcb4aa5316c1", algorithm, 499, "ke1235");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("init-hex:5bf075d9959d036f:md5 499 ke1235:3712dcb4aa5316c1", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Ignore("ELY-777")
    @Test
    public void testAuthenticationWithInitWordResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("3712dcb4aa5316c1").hexDecode().drain(),
                "ke1235", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, INIT_WORD_RESPONSE, "RED HERD NOW BEAN PA BURG", algorithm, 499, "ke1235");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            assertNotNull(saslClient);
            assertTrue(saslClient instanceof OTPSaslClient);
            assertTrue(saslClient.hasInitialResponse());
            assertFalse(saslClient.isComplete());

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("init-word:BOND FOGY DRAB NE RISE MART:md5 499 ke1235:RED HERD NOW BEAN PA BURG", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Ignore("ELY-777")
    @Test
    public void testAuthenticationWithLowSequenceNumber() throws Exception {
        mockSeed("lr4321");
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("eb65a876fd5e5e8e").hexDecode().drain(),
                "ke1234", 10)); // Low sequence number, the sequence should be reset
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("870c2dcc4fd6b474").hexDecode().drain(),
                "lr4321", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, INIT_WORD_RESPONSE, "My new pass phrase");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 9 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("init-word:HOYT ATE SARA DISH REED OUST:md5 499 lr4321:FULL BUSS DIET ITCH CORK SAM", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }


    @Test
    public void testAuthenticationWithMultiWordOTPWithAlternateDictionary() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            Map<String, Object> props = new HashMap<String, Object>();
            props.put(WildFlySasl.OTP_ALTERNATE_DICTIONARY, OTPSaslClientFactory.dictionaryArrayToProperty(ALTERNATE_DICTIONARY));
            final CallbackHandler cbh = createClientCallbackHandler("userName", "sars zike zub sahn siar pft", DIRECT_OTP, algorithm, WORD_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    props, cbh);


            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:sars zike zub sahn siar pft", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }


    @Test
    public void testAuthenticationWithPassPhraseWithAlternateDictionary() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslServerFactory serverFactory = obtainSaslServerFactory(OTPSaslServerFactory.class);
        assertNotNull(serverFactory);
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            Map<String, Object> props = new HashMap<String, Object>();
            props.put(WildFlySasl.OTP_ALTERNATE_DICTIONARY, OTPSaslClientFactory.dictionaryArrayToProperty(OTPTest.ALTERNATE_DICTIONARY));
            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, WORD_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    props, cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertEquals("word:sars zike zub sahn siar pft", new String(message, StandardCharsets.UTF_8));
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertTrue(saslServer.isComplete());
            assertNull(message);
            assertEquals("userName", saslServer.getAuthorizationID());

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testMultipleSimultaneousAuthenticationSessions() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();

        final SaslServerBuilder serverBuilder1 = createSaslServerBuilder(password, closeableReference, securityDomainReference);
        try {
            final SaslServer saslServer1 = serverBuilder1.build();
            final SaslServer saslServer2 = serverBuilder1.copy(true).build();

            final CallbackHandler cbh = createClientCallbackHandler("userName", "BOND FOGY DRAB NE RISE MART", DIRECT_OTP, algorithm, WORD_RESPONSE);
            final SaslClient saslClient1 = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);
            final SaslClient saslClient2 = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            final ExecutorService executorService = Executors.newFixedThreadPool(2);
            final Callable<Boolean> attempt1 = () -> {
                boolean attemptFailed = false;
                byte[] message1 = saslClient1.evaluateChallenge(new byte[0]);
                message1 = saslServer1.evaluateResponse(message1);
                message1 = saslClient1.evaluateChallenge(message1);
                try {
                    saslServer1.evaluateResponse(message1);
                } catch (SaslException e) {
                    attemptFailed = true;
                    saslServer1.dispose();
                }
                return attemptFailed;
            };
            final Callable<Boolean> attempt2 = () -> {
                boolean attemptFailed = false;
                byte[] message2 = saslClient2.evaluateChallenge(new byte[0]);
                message2 = saslServer2.evaluateResponse(message2);
                message2 = saslClient2.evaluateChallenge(message2);
                try {
                    saslServer2.evaluateResponse(message2);
                } catch (SaslException e) {
                    attemptFailed = true;
                    saslServer2.dispose();
                }
                return attemptFailed;
            };

            Future<Boolean> result1, result2;
            try {
                result1 = executorService.submit(attempt1);
                result2 = executorService.submit(attempt2);
            } finally {
                executorService.shutdown();
            }

            boolean attempt1Failed = result1.get();
            boolean attempt2Failed = result2.get();
            if ((attempt1Failed && attempt2Failed) || (! attempt1Failed && ! attempt2Failed)) {
                fail("Exactly one of the authentication attempts should have succeeded");
            }

            // Check the password is updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }


    // -- Unsuccessful authentication exchanges --

    @Test
    public void testAuthenticationWithWrongPassword() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "TONE NELL RACY GRIN ROOM GELD", DIRECT_OTP, algorithm, WORD_RESPONSE); // Wrong password
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            assertFalse(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            assertFalse(saslServer.isComplete());
            assertFalse(saslClient.isComplete());

            message = saslClient.evaluateChallenge(message);
            assertTrue(saslClient.isComplete());
            assertFalse(saslServer.isComplete());

            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
            saslClient.dispose();
            saslServer.dispose();

            // The password should remain unchanged
            checkPassword(securityDomainReference, "userName", (OneTimePassword) password, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithWrongPasswordInInitResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "GAFF WAIT SKID GIG SKY EYED", DIRECT_OTP, algorithm, INIT_WORD_RESPONSE, "RED HERD NOW BEAN PA BURG", algorithm, 500, "ke1235");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));
            message = saslClient.evaluateChallenge(message);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
            saslClient.dispose();
            saslServer.dispose();

            // The password should remain unchanged
            checkPassword(securityDomainReference, "userName", (OneTimePassword) password, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithInvalidNewPasswordInInitResponse() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("5bf075d9959d036f").hexDecode().drain(),
                "ke1234", 499));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "BOND FOGY DRAB NE RISE MART", DIRECT_OTP, algorithm, INIT_WORD_RESPONSE, "RED HERD NOW BEAN PA BURG", algorithm, 499, "ke1235");
            final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.OTP }, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            assertEquals("otp-md5 499 ke1234 ext", new String(message, StandardCharsets.UTF_8));

            // Construct an init-word response with a valid current OTP but an invalid new OTP
            message = "init-word:BOND FOGY DRAB NE RISE MART:md5 0 !ke1235$:RED".getBytes(StandardCharsets.UTF_8);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
            saslClient.dispose();
            saslServer.dispose();

            // The password should be updated to the current OTP
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithInvalidPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                "ke1234", 500));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "tooShort", PASS_PHRASE, algorithm, HEX_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            try {
                saslClient.evaluateChallenge(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
            saslClient.dispose();
            saslServer.dispose();

            // The password should remain unchanged
            checkPassword(securityDomainReference, "userName", (OneTimePassword) password, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    @Test
    public void testAuthenticationWithLongSeed() throws Exception {
        testPasswordRemainsUnchanged("thisSeedIsTooLong", 500);
    }

    @Test
    public void testAuthenticationWithNonAlphanumericSeed() throws Exception {
        testPasswordRemainsUnchanged("A seed!", 500);
    }


    @Test
    public void testAuthenticationWithInvalidSequenceNumber() throws Exception {
        testPasswordRemainsUnchanged("ke1234", 0);
    }

    @Test
    public void testGeneratePasswordFromPassPhrase() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt", 100));

        OneTimePasswordAlgorithmSpec otpSpec = new OneTimePasswordAlgorithmSpec(algorithm, "TeSt", 100);
        EncryptablePasswordSpec passwordSpec = new EncryptablePasswordSpec("This is a test.".toCharArray(), otpSpec);
        OneTimePassword generatedOTPassword = (OneTimePassword) passwordFactory.generatePassword(passwordSpec);

        assertTrue(password.equals(generatedOTPassword));
    }

    @Test
    public void testUnauthorizedAuthorizationId() throws Exception {
        final String algorithm = ALGORITHM_OTP_SHA1;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("103029b112deb117").hexDecode().drain(),
                "TeSt", 100));
        OneTimePassword expectedUpdatedPassword = (OneTimePassword) passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("87fec7768b73ccf9").hexDecode().drain(),
                "TeSt", 99));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, HEX_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, "wrongName", "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            message = saslServer.evaluateResponse(message);
            message = saslClient.evaluateChallenge(message);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
            saslClient.dispose();
            saslServer.dispose();

            // The password should be updated
            checkPassword(securityDomainReference, "userName", expectedUpdatedPassword, algorithm);
        } finally {
            closeableReference.getReference().close();
        }
    }

    private SaslServerBuilder createSaslServerBuilder(Password password, BuilderReference<Closeable> closeableReference, BuilderReference<SecurityDomain> securityDomainReference) {
        SaslServerBuilder builder = new SaslServerBuilder(OTPSaslServerFactory.class, SaslMechanismInformation.Names.OTP)
                .setModifiableRealm()
                .setUserName("userName")
                .setPassword(password)
                .setModifiableRealm()
                .setProtocol("test")
                .setServerName("testserver1.example.com")
                .registerCloseableReference(closeableReference)
                .registerSecurityDomainReference(securityDomainReference);
        return builder;
    }

    private SaslServer createSaslServer(Password password, BuilderReference<Closeable> closeableReference, BuilderReference<SecurityDomain> securityDomainReference) throws IOException {
        SaslServer saslServer = createSaslServerBuilder(password, closeableReference, securityDomainReference)
                .build();
        assertFalse(saslServer.isComplete());
        return saslServer;
    }

    private void checkPassword(BuilderReference<SecurityDomain> domainReference, String userName,
                               OneTimePassword expectedUpdatedPassword, String algorithmName) throws RealmUnavailableException {
        SecurityDomain securityDomain = domainReference.getReference();
        RealmIdentity realmIdentity = securityDomain.getIdentity(userName);
        OneTimePassword updatedPassword = realmIdentity.getCredential(PasswordCredential.class, algorithmName).getPassword(OneTimePassword.class);

        assertEquals(expectedUpdatedPassword.getAlgorithm(), updatedPassword.getAlgorithm());
        assertArrayEquals(expectedUpdatedPassword.getHash(), updatedPassword.getHash());
        assertEquals(expectedUpdatedPassword.getSeed(), updatedPassword.getSeed());
        assertEquals(expectedUpdatedPassword.getSequenceNumber(), updatedPassword.getSequenceNumber());
        realmIdentity.dispose();
    }

    private void mockSeed(final String randomStr){
        new MockUp<OTPUtil>(){
            @Mock
            String generateRandomAlphanumericString(int length, Random random){
                return randomStr;
            }
        };
    }

    private CallbackHandler createClientCallbackHandler(String username, String password, String passwordFormatChoice, String algorithm, String responseChoice) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .useChoice(MATCH_RESPONSE_CHOICE, responseChoice)
                                .useChoice(MATCH_PASSWORD_FORMAT_CHOICE, passwordFormatChoice)
                                .usePassword(password)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(algorithm)));

        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    private CallbackHandler createClientCallbackHandler(String username, String password, String passwordFormatChoice, String algorithm, String responseChoice, String newPassword,
                                                        String newAlgorithm, int newSequenceNumber, String newSeed) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .useChoice(MATCH_RESPONSE_CHOICE, responseChoice)
                                .useChoice(MATCH_PASSWORD_FORMAT_CHOICE, passwordFormatChoice)
                                .usePassword(password)
                                .useChoice(MATCH_NEW_PASSWORD_FORMAT_CHOICE, DIRECT_OTP)
                                .useParameterSpec(getOTPParameterSpec(newAlgorithm, newSeed, newSequenceNumber))
                                .useCallbackHandler(callbacks -> {
                                    if (callbacks.length > 0) {
                                        final Callback callback = callbacks[0];
                                        if (callback instanceof PasswordResetCallback) {
                                            ((PasswordResetCallback) callback).setPassword(newPassword.toCharArray());
                                        } else {
                                            CallbackUtil.unsupported(callback);
                                        }
                                    }
                                }, EnumSet.of(CallbackKind.CREDENTIAL_RESET))
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(algorithm)));

        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    private CallbackHandler createClientCallbackHandler(String username, String password, String passwordFormatChoice, String algorithm, String responseChoice, String newPassPhrase) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .useChoice(MATCH_RESPONSE_CHOICE, responseChoice)
                                .useChoice(MATCH_PASSWORD_FORMAT_CHOICE, passwordFormatChoice)
                                .usePassword(password)
                                .useChoice(MATCH_NEW_PASSWORD_FORMAT_CHOICE, PASS_PHRASE)
                                .useCallbackHandler(callbacks -> {
                                    if (callbacks.length > 0) {
                                        final Callback callback = callbacks[0];
                                        if (callback instanceof PasswordResetCallback) {
                                            ((PasswordResetCallback) callback).setPassword(newPassPhrase.toCharArray());
                                        } else {
                                            CallbackUtil.unsupported(callback);
                                        }
                                    }
                                }, EnumSet.of(CallbackKind.CREDENTIAL_RESET))
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(algorithm)));

        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    private void testPasswordRemainsUnchanged(String seed, int sequenceNumber) throws Exception {
        final String algorithm = ALGORITHM_OTP_MD5;
        final SaslClientFactory clientFactory = obtainSaslClientFactory(OTPSaslClientFactory.class);
        assertNotNull(clientFactory);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
        final Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(CodePointIterator.ofString("505d889f90085847").hexDecode().drain(),
                seed, sequenceNumber));
        final SaslServerBuilder.BuilderReference<SecurityDomain> securityDomainReference = new SaslServerBuilder.BuilderReference<>();
        final SaslServerBuilder.BuilderReference<Closeable> closeableReference = new SaslServerBuilder.BuilderReference<>();
        try {
            final SaslServer saslServer = createSaslServer(password, closeableReference, securityDomainReference);

            final CallbackHandler cbh = createClientCallbackHandler("userName", "This is a test.", PASS_PHRASE, algorithm, HEX_RESPONSE);
            final SaslClient saslClient = clientFactory.createSaslClient(new String[]{SaslMechanismInformation.Names.OTP}, null, "test", "testserver1.example.com",
                    Collections.<String, Object>emptyMap(), cbh);

            byte[] message = saslClient.evaluateChallenge(new byte[0]);
            try {
                saslServer.evaluateResponse(message);
                fail("Expected SaslException not thrown");
            } catch (SaslException expected) {
            }
            saslClient.dispose();
            saslServer.dispose();

            // The password should remain unchanged
            checkPassword(securityDomainReference, "userName", (OneTimePassword) password, algorithm);
        } finally {
            closeableReference.getReference().close();
        }

    }

    private static final String[] ALTERNATE_DICTIONARY = new String[] {
        "poel",   "qewn",   "xlob",   "preg",   "qome",   "zarm",   "sas",
        "oerk",   "sct",    "seb",    "ilan",   "wct",    "bp",     "sft",
        "beys",   "rela",   "iieu",   "oive",   "ncme",   "xila",   "znch",
        "zd",     "zeaf",   "oabe",   "odge",   "xmes",   "zore",   "xudo",
        "qial",   "rmid",   "pibe",   "phud",   "yife",   "wund",   "rjar",
        "qal",    "zlma",   "wgee",   "wlma",   "rids",   "reak",   "qoff",
        "xob",    "abark",  "zdge",   "zdds",   "zina",   "zord",   "qloe",
        "xeta",   "qoke",   "pcon",   "qerg",   "oide",   "pvid",   "plen",
        "yvid",   "xers",   "sart",   "qden",   "ffct",   "qkat",   "zage",
        "sbis",   "zite",   "slec",   "poft",   "ccugh",  "zie",    "ses",
        "wred",   "pec",    "abnt",   "ohay",   "rkay",   "hab",    "zake",
        "qar",    "wcid",   "oord",   "xeed",   "zumb",   "prue",   "zdit",
        "wrae",   "pose",   "zild",   "iute",   "iude",   "sote",   "qlan",
        "rway",   "pao",    "qach",   "paas",   "sye",    "xahn",   "zeys",
        "sued",   "zbel",   "xobo",   "bbuns",  "nhaw",   "oad",    "qlee",
        "xse",    "pldy",   "bord",   "woke",   "zcme",   "zeam",   "xobe",
        "xrub",   "zaft",   "yalk",   "oida",   "ccim",   "zale",   "ztc",
        "qiew",   "zld",    "qeek",   "zyra",   "peb",    "sela",   "haut",
        "ohar",   "zad",    "qund",   "ooge",   "saut",   "pae",    "qeo",
        "zddy",   "oyed",   "zsed",   "zlse",   "surd",   "zire",   "pava",
        "bct",    "pham",   "bem",    "zem",    "oile",   "oarl",   "zrb",
        "seda",   "oule",   "wde",    "ierg",   "zerk",   "sens",   "zag",
        "zibs",   "sert",   "zank",   "perb",   "qoal",   "npa",    "bloe",
        "sesk",   "oao",    "ske",    "zwe",    "rild",   "onew",   "qage",
        "xric",   "rald",   "zudd",   "deent",  "xsle",   "abaul",  "sean",
        "seth",   "zic",    "sayo",   "qce",    "qcme",   "aarig",  "peo",
        "xac",    "slee",   "qak",    "abhan",  "ccsks",  "qlaf",   "stah",
        "hed",    "pobs",   "qah",    "pieu",   "poat",   "ooe",    "wudy",
        "qiet",   "owan",   "xud",    "wyde",   "hcts",   "quck",   "iawd",
        "zure",   "seir",   "iudy",   "paby",   "hebt",   "bbbe",   "swe",
        "zrau",   "yess",   "xhub",   "nwab",   "zhat",   "phoa",   "xome",
        "zben",   "zile",   "pah",    "soch",   "bebe",   "zids",   "zaf",
        "srid",   "sesh",   "ccag",   "qmra",   "pife",   "rtem",   "qoer",
        "weny",   "zap",    "xabe",   "pary",   "rhoa",   "sosa",   "qhew",
        "xief",   "sfar",   "soat",   "zila",   "hval",   "reaf",   "zoof",
        "hatt",   "pnee",   "zam",    "qeem",   "pube",   "xao",    "zeat",
        "zans",   "onch",   "pide",   "plod",   "reys",   "poff",   "rawl",
        "peah",   "zene",   "pair",   "zlec",   "wbed",   "oid",    "zret",
        "bda",    "rvan",   "reir",   "qda",    "rtar",   "zobo",   "rte",
        "zlaw",   "qmes",   "saft",   "aaont",  "zame",   "pobo",   "sda",
        "plak",   "xeat",   "serm",   "zole",   "sind",   "zang",   "zcre",
        "pdgy",   "iaft",   "ccis",   "qee",    "xona",   "xcta",   "zial",
        "pait",   "ziet",   "peid",   "ioad",   "znna",   "qmid",   "haby",
        "ptag",   "zeen",   "pkat",   "ssle",   "hree",   "zct",    "bwk",
        "pade",   "zeft",   "peon",   "zowe",   "pyde",   "pled",   "purb",
        "roah",   "zuod",   "pram",   "xasy",   "pche",   "xark",   "shet",
        "sucy",   "sbey",   "abben",  "xick",   "zola",   "wesh",   "xuck",
        "hdna",   "zalo",   "rloe",   "peat",   "qona",   "ooco",   "slod",
        "poam",   "zoft",   "ynne",   "pdin",   "itab",   "poga",   "xlaw",
        "rair",   "qret",   "sahn",   "xola",   "xien",   "xtay",   "denus",
        "rrb",    "zome",   "xnna",   "zran",   "zwab",   "deahn",  "pmra",
        "xrid",   "qumb",   "zalt",   "xulb",   "sram",   "pomb",   "oawk",
        "zaas",   "smra",   "qine",   "zoff",   "zyle",   "wnub",   "zerg",
        "ztan",   "rmma",   "zeb",    "xalk",   "plad",   "olad",   "wuck",
        "qnee",   "pem",    "soer",   "sgee",   "znte",   "pere",   "sein",
        "psia",   "xoan",   "hrea",   "sree",   "neer",   "zice",   "pmes",
        "xery",   "rard",   "ilba",   "zhay",   "seft",   "snca",   "zond",
        "qhet",   "slaw",   "aberk",  "qeak",   "snee",   "zelm",   "xala",
        "plla",   "rpe",    "zoat",   "poyd",   "xale",   "bec",    "otab",
        "iuct",   "abeta",  "sibe",   "znub",   "soal",   "puna",   "byde",
        "xcar",   "zift",   "zurf",   "xtag",   "zace",   "zrge",   "sao",
        "zode",   "bnee",   "shem",   "qver",   "sray",   "zlee",   "qeam",
        "zeg",    "pfar",   "pass",   "zuna",   "xood",   "xcid",   "qeah",
        "xerr",   "reet",   "qlec",   "okat",   "aaray",  "owag",   "hmid",
        "xisa",   "yild",   "qben",   "qoda",   "zva",    "sose",   "qena",
        "qcho",   "piern",  "zne",    "hlaw",   "aaair",  "sass",   "phee",
        "sisc",   "sies",   "xrab",   "wes",    "pld",    "smma",   "qve",
        "nree",   "pcat",   "sed",    "qed",    "zoga",   "zcts",   "znag",
        "zloe",   "xove",   "sawd",   "sawl",   "aavow",  "iait",   "zomb",
        "sona",   "quft",   "hina",   "oarm",   "scho",   "zven",   "otem",
        "ibut",   "sute",   "sey",    "bult",   "xacy",   "zrea",   "pear",
        "zive",   "xnee",   "pace",   "ztch",   "hody",   "igan",   "soam",
        "zel",    "sran",   "qame",   "slak",   "qall",   "nise",   "surb",
        "qab",    "zal",    "qnds",   "znee",   "phoe",   "zasy",   "ccogo",
        "zcid",   "zlba",   "qarb",   "iate",   "salf",   "pech",   "reil",
        "rwen",   "oant",   "pre",    "hase",   "zham",   "seef",   "pald",
        "qoge",   "perd",   "zhub",   "otah",   "zlub",   "sewt",   "sask",
        "xike",   "zse",    "qoed",   "plue",   "pudy",   "xold",   "scy",
        "plaw",   "peny",   "pays",   "zaid",   "iray",   "seno",   "iome",
        "ggeys",  "zcon",   "sody",   "oars",   "zbey",   "zep",    "perg",
        "pbey",   "xas",    "pebt",   "bkit",   "xesh",   "zvid",   "zewn",
        "zke",    "ztab",   "poch",   "smen",   "qven",   "sff",    "zich",
        "snch",   "oagy",   "zkew",   "xone",   "abup",   "pied",   "zess",
        "nena",   "ppe",    "zabe",   "purd",   "haws",   "oona",   "zed",
        "zend",   "xham",   "prch",   "sld",    "ierr",   "qrae",   "zhem",
        "blga",   "oery",   "iien",   "scon",   "poge",   "qima",   "sant",
        "ccda",   "zgan",   "pate",   "zeth",   "iift",   "phod",   "zgee",
        "zoey",   "bemo",   "qran",   "zamb",   "zert",   "hden",   "pibs",
        "zane",   "pain",   "zbed",   "ihef",   "rola",   "sany",   "abkin",
        "ste",    "pwam",   "rran",   "soid",   "zlay",   "xlea",   "btab",
        "rarl",   "hawl",   "nerk",   "zway",   "zeef",   "xlod",   "zoad",
        "pord",   "pab",    "qell",   "zuel",   "zima",   "zena",   "hiew",
        "xota",   "wice",   "zuge",   "zucy",   "zady",   "yaud",   "owen",
        "zlue",   "zeah",   "sief",   "pile",   "zens",   "abida",  "zebe",
        "zaw",    "iel",    "qyed",   "rra",    "yone",   "past",   "simb",
        "rees",   "soke",   "pver",   "hane",   "pral",   "xual",   "plew",
        "oest",   "zhef",   "iiar",   "zisc",   "oddy",   "rhed",   "plid",
        "zyed",   "siet",   "yart",   "sldy",   "iurf",   "sjar",   "halk",
        "zee",    "iual",   "qhe",    "roca",   "soel",   "pdd",    "ouct",
        "qana",   "poke",   "sava",   "xand",   "sald",   "xeir",   "zood",
        "saf",    "xebt",   "ztub",   "ymes",   "wela",   "puft",   "qalt",
        "wman",   "zary",   "zain",   "zayo",   "humb",   "odit",   "xdle",
        "xear",   "ielt",   "qoat",   "serb",   "yats",   "sola",   "roga",
        "irag",   "zule",   "aat",    "zlam",   "pdds",   "heno",   "zey",
        "sboe",   "pee",    "xarm",   "qive",   "waby",   "pova",   "zoke",
        "sars",   "qask",   "xman",   "xise",   "pione",  "hagy",   "qhey",
        "oeed",   "xtem",   "sdea",   "shen",   "biet",   "poes",   "zude",
        "poah",   "hde",    "zib",    "ooga",   "oame",   "rie",    "hoat",
        "srch",   "pota",   "zatt",   "pieef",  "oena",   "xess",   "qawd",
        "zak",    "sret",   "ihay",   "zhan",   "zlan",   "olba",   "zime",
        "xoft",   "xuel",   "abiny",  "zard",   "icta",   "zair",   "sala",
        "zao",    "bift",   "zarb",   "zlia",   "yuds",   "denes",  "qoar",
        "rcts",   "zant",   "oawd",   "zrey",   "zoe",    "pas",    "swen",
        "xard",   "qrib",   "xcts",   "ioid",   "inub",   "oelf",   "zest",
        "peau",   "zes",    "zraw",   "ohaw",   "somb",   "aaerb",  "seto",
        "zlat",   "pnce",   "pids",   "zhoa",   "pven",   "brit",   "xowe",
        "sial",   "pnds",   "zarc",   "oap",    "qsle",   "ikay",   "oefy",
        "xawd",   "phet",   "phay",   "sdd",    "zewt",   "zern",   "zota",
        "zab",    "oear",   "snew",   "hoam",   "xel",    "ccx",    "solf",
        "zff",    "rlan",   "zuff",   "rady",   "rere",   "sde",    "qule",
        "xhic",   "zove",   "ddly",   "sume",   "patt",   "qief",   "xeth",
        "oero",   "oute",   "roak",   "oary",   "qoco",   "zlen",   "soof",
        "zlla",   "bgan",   "irue",   "pift",   "zeo",    "qoft",   "nuge",
        "sid",    "zoar",   "sble",   "roge",   "soed",   "sagy",   "oene",
        "pies",   "zte",    "wtag",   "rlba",   "zhet",   "phag",   "hven",
        "pboe",   "yens",   "xech",   "qrau",   "zibe",   "nfro",   "ccoat",
        "heak",   "qloc",   "iach",   "sild",   "zeed",   "zhen",   "pgan",
        "xue",    "oeo",    "ieek",   "zser",   "zobe",   "syte",   "zrib",
        "peil",   "bbant",  "oond",   "zuke",   "rhod",   "zpe",    "zaby",
        "suet",   "hade",   "seil",   "zays",   "aaabe",  "slla",   "nbut",
        "xnub",   "zwan",   "sien",   "rmra",   "pce",    "aaulk",  "qic",
        "oend",   "zelf",   "qays",   "zea",    "zube",   "syde",   "pild",
        "qlob",   "rlub",   "qact",   "sebe",   "aadds",  "qdam",   "sses",
        "xhef",   "pesk",   "znds",   "zwam",   "qobo",   "abdds",  "salm",
        "oeaf",   "bhy",    "xwan",   "qat",    "peen",   "rnub",   "qide",
        "qang",   "xak",    "zub",    "zram",   "zas",    "xesk",   "pard",
        "xldy",   "qelt",   "ohef",   "poco",   "iap",    "zent",   "xred",
        "xcme",   "sdam",   "xrc",    "qeef",   "sarn",   "sobe",   "pnes",
        "sudy",   "sond",   "zrae",   "qval",   "parb",   "qobs",   "zose",
        "zesk",   "ccid",   "iews",   "zmes",   "yoam",   "qood",   "puge",
        "iaas",   "qway",   "htan",   "qlma",   "buty",   "zeil",   "zae",
        "qne",    "qaut",   "zoel",   "sone",   "xoge",   "zoid",   "zenu",
        "pmen",   "zoak",   "pbut",   "xret",   "oarc",   "pd",     "qole",
        "zuct",   "xein",   "qift",   "oaag",   "part",   "pben",   "srue",
        "srod",   "sait",   "oays",   "qbey",   "seld",   "zna",    "wbe",
        "oove",   "qd",     "zrod",   "zune",   "serg",   "yeth",   "wao",
        "oich",   "wmid",   "bbris",  "zied",   "sird",   "xlue",   "zand",
        "pidy",   "zise",   "xrae",   "xite",   "scts",   "zuad",   "pang",
        "rara",   "ze",     "phad",   "xbut",   "xft",    "sune",   "xeg",
        "wero",   "zafe",   "qarr",   "wass",   "zldy",   "qess",   "boul",
        "sive",   "peno",   "sual",   "zike",   "rdge",   "poof",   "xea",
        "zoah",   "rnee",   "xode",   "zlva",   "pock",   "bary",   "ziar",
        "qvan",   "zdgy",   "zdle",   "sawn",   "deunt",  "bnob",   "qfro",
        "zmid",   "zlga",   "paff",   "zoda",   "iuge",   "ploc",   "zf",
        "sva",    "ried",   "zrue",   "plaf",   "oee",    "huds",   "pave",
        "pcho",   "znne",   "zets",   "zast",   "dero",   "pye",    "qurb",
        "xnch",   "oaas",   "seo",    "zda",    "srma",   "pawn",   "qibs",
        "xoca",   "qume",   "qnob",   "zkid",   "wora",   "zued",   "aaere",
        "zail",   "prau",   "hief",   "orae",   "pawk",   "rlid",   "ooda",
        "xwe",    "oias",   "znca",   "sudo",   "oea",    "sawk",   "pike",
        "qmen",   "zeau",   "qeon",   "yich",   "heer",   "bosa",   "bbour",
        "rlga",   "qime",   "zbe",    "bim",    "rvid",   "seau",   "oask",
        "abbed",  "serr",   "selt",   "rna",    "snds",   "prey",   "soud",
        "hdit",   "sre",    "zhaw",   "yue",    "zein",   "zde",    "oima",
        "pbet",   "zfro",   "oume",   "ioge",   "pare",   "sreg",   "woge",
        "sern",   "qte",    "oann",   "zeno",   "ptew",   "qoey",   "psed",
        "soge",   "prae",   "oora",   "sebt",   "orey",   "yias",   "qaud",
        "pees",   "shan",   "zpa",    "zhod",   "slad",   "aaoin",  "sndy",
        "zare",   "qrc",    "zlib",   "plib",   "slea",   "zhar",   "resh",
        "qarl",   "sarc",   "yven",   "qash",   "zyte",   "zled",   "zate",
        "buly",   "zree",   "zawl",   "plab",   "sdit",   "qldy",   "sord",
        "qbet",   "ploe",   "aarub",  "sarb",   "bbout",  "zbut",   "seg",
        "blo",    "pisc",   "xyed",   "zhe",    "indy",   "xrb",    "zffy",
        "zock",   "hnna",   "xcho",   "ynca",   "hasy",   "qart",   "puod",
        "zuch",   "srew",   "xask",   "xche",   "pote",   "qain",   "pess",
        "cctt",   "hdds",   "zela",   "pke",    "zman",   "xram",   "xeft",
        "suct",   "xlec",   "iood",   "abasy",  "pene",   "icme",   "slba",
        "hude",   "xne",    "stc",    "zoch",   "rsia",   "bila",   "xoe",
        "zias",   "xmma",   "ruba",   "oce",    "zhew",   "zote",   "yat",
        "sias",   "qurf",   "pdea",   "aarow",  "ound",   "pute",   "rimb",
        "zdna",   "pake",   "sral",   "zdam",   "rraw",   "zye",    "ywam",
        "zrad",   "rota",   "abutt",  "qond",   "aaure",  "zra",    "oeak",
        "oebe",   "wnna",   "sain",   "pct",    "pise",   "peem",   "ioal",
        "zagi",   "pak",    "zmma",   "ycta",   "zean",   "qdea",   "ress",
        "ipa",    "zid",    "slag",   "prag",   "oune",   "qgee",   "pebe",
        "pual",   "qqua",   "zyde",   "oiew",   "bbud",   "pail",   "rann",
        "sisa",   "zud",    "sady",   "omma",   "shic",   "ouba",   "zhic",
        "peck",   "qet",    "qtan",   "pome",   "pamb",   "oobs",   "nulf",
        "zone",   "pask",   "sess",   "ccahn",  "xval",   "qife",   "qrag",
        "ooud",   "quff",   "zawn",   "seud",   "zind",   "bbcre",  "zen",
        "oen",    "mnath",  "pefy",   "beah",   "irea",   "hran",   "slia",
        "samb",   "xeto",   "wib",    "peek",   "aaock",  "oacy",   "xurb",
        "sak",    "zebt",   "hucy",   "qep",    "wa",     "ieat",   "srea",
        "powa",   "bucy",   "senu",   "zver",   "ruft",   "quch",   "ryed",
        "pcy",    "xreg",   "heah",   "zere",   "parm",   "zhag",   "whic",
        "ylec",   "selm",   "xnds",   "zero",   "qawl",   "peed",   "skay",
        "qimb",   "zndy",   "ggale",  "qwe",    "pand",   "xlag",   "qest",
        "qre",    "olam",   "pcid",   "zce",    "abefy",  "qurd",   "soc",
        "perr",   "pine",   "ylaw",   "zuba",   "poad",   "sdge",   "rlob",
        "qoc",    "sowe",   "wabe",   "pbis",   "xake",   "pnag",   "bbdit",
        "rewt",   "rve",    "ptem",   "qeb",    "zash",   "ove",    "saws",
        "pase",   "zray",   "pier",   "puke",   "rrma",   "zhad",   "pwan",
        "xve",    "qdna",   "sene",   "zurb",   "xali",   "bwo",    "zble",
        "zve",    "wive",   "xank",   "zuck",   "rrab",   "sce",    "qrma",
        "bwry",   "sven",   "zear",   "zews",   "xrew",   "oden",   "zidy",
        "zqua",   "zah",    "rait",   "prad",   "pnd",    "wite",   "zew",
        "seon",   "ooam",   "pnna",   "aargo",  "zana",   "ive",    "hora",
        "suse",   "zhee",   "sdgy",   "hft",    "srib",   "zrew",   "zats",
        "zar",    "zerb",   "ywe",    "ohen",   "suck",   "peet",   "odds",
        "qkew",   "xima",   "oees",   "pumb",   "pwab",   "ccrad",  "oed",
        "pft",    "sae",    "okew",   "znob",   "pnne",   "zlod",   "zmra",
        "olen",   "xody",   "qpe",    "sase",   "zsia",   "hlab",   "qove",
        "zral",   "zath",   "puch",   "zany",   "hep",    "savy",   "zali",
        "qtew",   "sark",   "zagy",   "soma",   "oib",    "qke",    "peer",
        "rcta",   "sall",   "aareg",  "aaie",   "zeak",   "peir",   "slue",
        "shey",   "sude",   "squa",   "whod",   "qrew",   "zata",   "poma",
        "qtc",    "zrag",   "aawam",  "pda",    "sida",   "zier",   "pach",
        "xwag",   "qnag",   "yal",    "qode",   "qrch",   "qeud",   "zemo",
        "zead",   "sdds",   "plma",   "sade",   "qhay",   "shar",   "sata",
        "ooey",   "xild",   "iep",    "qast",   "shat",   "qeto",   "za",
        "qerk",   "xlid",   "yota",   "shoa",   "zcot",   "wlag",   "sast",
        "saff",   "qeau",   "oire",   "qrud",   "qhan",   "zurd",   "sate",
        "qlen",   "pnew",   "znce",   "parr",   "pcot",   "srae",   "xall",
        "zrid",   "qaur",   "zlob",   "ooal",   "ssia",   "pack",   "iah",
        "qual",   "pree",   "zcar",   "xree",   "pcre",   "suod",   "sche",
        "hace",   "zalm",   "zmen",   "pali",   "zick",   "znd",    "sova",
        "qudo",   "zay",    "xaft",   "zudo",   "qacy",   "hhat",   "zark",
        "pud",    "slva",   "xine",   "ises",   "ilad",   "oact",   "ocre",
        "zses",   "nark",   "sbel",   "zjar",   "bbar",   "zeta",   "xeld",
        "sloc",   "hlec",   "zeon",   "rd",     "powe",   "pndy",   "sats",
        "xase",   "rowa",   "webe",   "xhey",   "xure",   "ouby",   "zoca",
        "wlva",   "nlam",   "sair",   "xoal",   "xdge",   "ycid",   "qein",
        "seet",   "ihoe",   "xdgy",   "bos",    "qech",   "rhey",   "rask",
        "zida",   "pnob",   "abhe",   "plva",   "wse",    "pude",   "nefy",
        "zlid",   "wlad",   "poal",   "oeam",   "oofa",   "ieaf",   "pret",
        "salo",   "oess",   "saby",   "qand",   "qied",   "xenu",   "sulb",
        "yeer",   "paur",   "hbis",   "renu",   "qeld",   "qard",   "qava",
        "zerd",   "spe",    "hage",   "qaag",   "snne",   "iudd",   "siar",
        "satt",   "suby",   "qyra",   "zfar",   "hdea",   "sic",    "iell",
        "snte",   "aaane",  "zche",   "qib",    "zach",   "oyle",   "zase",
        "zcta",   "iuna",   "zden",   "hte",    "yoge",   "zac",    "sund",
        "pawd",   "iab",    "zalk",   "qaws",   "helt",   "rbed",   "qhee",
        "qune",   "zec",    "zeld",   "wava",   "zona",   "rial",   "inew",
        "yldy",   "poer",   "sf",     "suna",   "zell",   "xway",   "oech",
        "zald",   "soah",   "zold",   "qafe",   "zhey",   "oeel",   "zeer",
        "zdd",    "xlew",   "xraw",   "zora",   "hcot",   "pdle",   "peld",
        "rcy",    "xff",    "qtah",   "src",    "zawk",   "qes",    "aaata",
        "bban",   "ptay",   "zsle",   "xune",   "slma",   "sube",   "zann",
        "ser",    "zoma",   "xeda",   "shee",   "iman",   "pody",   "qeal",
        "suel",   "iben",   "qies",   "slse",   "prge",   "zeir",   "srb",
        "peft",   "qf",     "sep",    "aaoma",  "sah",    "ylam",   "rody",
        "soyd",   "htew",   "zaul",   "zara",   "rrae",   "xair",   "xule",
        "snce",   "ilaw",   "zwen",   "qtem",   "qoad",   "seah",   "sena",
        "pelm",   "suad",   "zack",   "bbol",   "aaear",  "snna",   "zoyd",
        "iarm",   "saur",   "zass",   "zolf",   "aaslo",  "ielf",   "zesh",
        "zoc",    "zulf",   "zeff",   "sake",   "pkid",   "hoan",   "zeel",
        "qate",   "pcan",   "zimb",   "xarc",   "zreg",   "bbery",  "zft",
        "oemo",   "pens",   "peaf",   "yche",   "path",   "sval",   "shub",
        "zade",   "zeck",   "rlam",   "sove",   "qyle",   "soan",   "ztah",
        "qnna",   "zbis",   "qlva",   "zrc",    "sne",    "zuet",   "aaid",
        "zide",   "hibs",   "ziew",   "bars",   "parn",   "paws",   "oep",
        "xiar",   "qcre",   "zlad",   "ocid",   "pure",   "xag",    "zre",
        "paud",   "poc",    "zhud",   "ofro",   "zhed",   "zboe",   "qct",
        "wtew",   "ilub",   "zeud",   "pyte",   "zuds",   "xrch",   "srek",
        "peef",   "zcat",   "obed",   "zue",    "zobs",   "xate",   "rhew",
        "zoaf",   "pets",   "zars",   "qobe",   "zody",   "qhef",   "oova",
        "pirab",  "sna",    "slub",   "qtay",   "sben",   "zact",   "zod",
        "sach",   "qebt",   "sarl",   "qmma",   "zute",   "phew",   "qeth",
        "zcy",    "zan",    "zrub",   "oelt",   "aary",   "zred",   "xlan",
        "qeed",   "yeck",   "abead",  "payo",   "qrea",   "wcho",   "zrud",
        "zavy",   "rcar",   "xume",   "zarr",   "sred",   "irew",   "qeg",
        "prid",   "qde",    "ptch",   "bant",   "wrud",   "zala",   "hime",
        "soca",   "ygee",   "pbed",   "pwat",   "hvid",   "olaw",   "sudd",
        "zura",   "sagi",   "zaws",   "xmen",   "xloc",   "xra",    "nnew",
        "rind",   "oase",   "zahn",   "xond",   "oas",    "qem",    "qath",
        "iobe",   "peda",   "zefy",   "qses",   "xeil",   "bwat",   "srag",
        "zlea",   "zaud",   "ptub",   "sve",    "zob",    "qse",    "zbet",
        "qike",   "zall",   "friend", "zeem",   "zoam",   "zrch",   "soe",
        "zerr",   "znew",   "rune",   "smes",   "zerm",   "oail",   "zeek",
        "yurf",   "pyed",   "xalm",   "yloc",   "ondy",   "pawl",   "oudo",
        "zarn",   "wtay",   "pane",   "zlew",   "pudd",   "svid",   "hali",
        "ztar",   "aayed",  "sann",   "olue",   "puff",   "oaur",   "sarr",
        "hars",   "ouds",   "wbut",   "oloc",   "perm",   "waws",   "qid",
        "aaoud",  "zer",    "qina",   "sib",    "qeil",   "zulb",   "zhoe",
        "rld",    "pata",   "rac",    "otub",   "zelt",   "zkat",   "poud",
        "rerk",   "zlab",   "wble",   "ccep",   "plub",   "zeet",   "ztag",
        "snes",   "qwag",   "peud",   "hoyd",   "qcid",   "pind",   "boun",
        "rwe",    "yoft",   "zuby",   "zaut",   "para",   "rnag",   "pcts",
        "zees",   "qert",   "zoco",   "hhad",   "hello",  "qcta",   "zric",
        "xias",   "qake",   "ruds",   "sie",    "phem",   "oent",   "qlew",
        "pird",   "oura",   "zlak",   "ieg",    "pash",   "hice",   "qcts",
        "iet",    "ioam",   "zarl",   "znes",   "peak",   "oeda",   "xloe",
        "bm",     "zudy",   "nve",    "qod"};
}

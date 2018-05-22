/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.digest;

import static org.wildfly.security._private.ElytronMessages.saslDigest;
import static org.wildfly.security.mechanism.digest.DigestUtil.parseResponse;
import static org.wildfly.security.sasl.digest._private.DigestUtil.H_A1;
import static org.wildfly.security.sasl.digest._private.DigestUtil.QOP_AUTH;
import static org.wildfly.security.sasl.digest._private.DigestUtil.QOP_AUTH_CONF;
import static org.wildfly.security.sasl.digest._private.DigestUtil.QOP_VALUES;
import static org.wildfly.security.sasl.digest._private.DigestUtil.digestResponse;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.common.Assert;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.digest.DigestQuote;

/**
 * A server implementation of RFC 2831 {@code DIGEST} SASL mechanism.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
final class DigestSaslServer extends AbstractDigestMechanism implements SaslServer {

    private final Predicate<String> digestUriProtocolAccepted;
    private final boolean defaultRealm; // realms not defined, server name used as fallback

    DigestSaslServer(String[] realms, final boolean defaultRealm, String mechanismName, String protocol, String serverName, CallbackHandler callbackHandler, Charset charset, String[] qops, String[] ciphers, Predicate<String> digestUriProtocolAccepted, Supplier<Provider[]> providers) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler, FORMAT.SERVER, charset, ciphers, providers);
        this.realms = realms;
        this.defaultRealm = defaultRealm;
        this.supportedCiphers = getSupportedCiphers(ciphers);
        this.qops = qops;
        this.digestUriProtocolAccepted = digestUriProtocolAccepted;
    }

    private static final byte STEP_ONE = 1;
    private static final byte STEP_THREE = 3;

    private String[] realms;
    private String supportedCiphers;
    private int receivingMaxBuffSize = DEFAULT_MAXBUF;
    private String[] qops;
    private int nonceCount = -1;
    private String receivedClientUri;
    private String boundServerName = null;

    /**
     * Generates a digest challenge
     *
     *    digest-challenge  =
     *    1#( realm | nonce | qop-options | stale | maxbuf | charset
     *          algorithm | cipher-opts | auth-param )
     *
     *   realm             = "realm" "=" <"> realm-value <">
     *   realm-value       = qdstr-val
     *   nonce             = "nonce" "=" <"> nonce-value <">
     *   nonce-value       = qdstr-val
     *   qop-options       = "qop" "=" <"> qop-list <">
     *   qop-list          = 1#qop-value
     *   qop-value         = "auth" | "auth-int" | "auth-conf" |
     *                        token
     *   stale             = "stale" "=" "true"
     *   maxbuf            = "maxbuf" "=" maxbuf-value
     *   maxbuf-value      = 1*DIGIT
     *   charset           = "charset" "=" "utf-8"
     *   algorithm         = "algorithm" "=" "md5-sess"
     *   cipher-opts       = "cipher" "=" <"> 1#cipher-value <">
     *   cipher-value      = "3des" | "des" | "rc4-40" | "rc4" |
     *                       "rc4-56" | token
     *   auth-param        = token "=" ( token | quoted-string )
     * @return
     */
    private byte[] generateChallenge() {
        ByteStringBuilder challenge = new ByteStringBuilder();

        // realms
        StringBuilder sb = new StringBuilder();
        for (String realm: this.realms) {
            sb.append("realm=\"").append(DigestQuote.quote(realm)).append("\"").append(DELIMITER);
        }
        challenge.append(sb.toString().getBytes(getCharset()));


        // nonce
        assert nonce == null;
        nonce = generateNonce();
        challenge.append("nonce=\"");
        challenge.append(DigestQuote.quote(nonce));
        challenge.append("\"").append(DELIMITER);

        // qop
        if (qops != null) {
            challenge.append("qop=\"");
            boolean first = true;
            for(String qop : qops){
                if(!first) challenge.append(DELIMITER);
                first = false;
                challenge.append(DigestQuote.quote(qop));
            }
            challenge.append("\"").append(DELIMITER);
        }

        // maxbuf
        if (receivingMaxBuffSize != DEFAULT_MAXBUF) {
            challenge.append("maxbuf=");
            challenge.append(String.valueOf(receivingMaxBuffSize));
            challenge.append(DELIMITER);
        }

        // charset
        if (StandardCharsets.UTF_8.equals(getCharset())) {
            challenge.append("charset=");
            challenge.append("utf-8");
            challenge.append(DELIMITER);
        }

        // cipher
        if (supportedCiphers != null && qops != null && arrayContains(qops, QOP_AUTH_CONF)) {
            challenge.append("cipher=\"");
            challenge.append(supportedCiphers);
            challenge.append("\"").append(DELIMITER);
        }

        challenge.append("algorithm=md5-sess"); // only for backwards compatibility with HTTP Digest

        return challenge.toArray();
    }

    private void noteDigestResponseData(HashMap<String, byte[]> parsedDigestResponse) {
        byte[] data = parsedDigestResponse.get("nc");
        if (data != null) {
            nonceCount = Integer.parseInt(new String(data, StandardCharsets.UTF_8));
        } else {
            nonceCount = -1;
        }

        data = parsedDigestResponse.get("cipher");
        if (data != null) {
            cipher = new String(data, StandardCharsets.UTF_8);
        } else {
            cipher = "";
        }

        data = parsedDigestResponse.get("authzid");
        if (data != null) {
            authorizationId = new String(data, StandardCharsets.UTF_8);
        } else {
            authorizationId = null;
        }
    }

    private byte[] validateDigestResponse(HashMap<String, byte[]> parsedDigestResponse) throws SaslException {
        if (nonceCount != 1) {
            throw saslDigest.mechNonceCountMustEqual(1, nonceCount).toSaslException();
        }

        Charset clientCharset = StandardCharsets.ISO_8859_1;
        if (parsedDigestResponse.get("charset") != null) {
            String cCharset = new String(parsedDigestResponse.get("charset"), StandardCharsets.UTF_8);
            if (cCharset.equals("utf-8")) {
                if (StandardCharsets.UTF_8.equals(getCharset())) {
                    clientCharset = StandardCharsets.UTF_8;
                } else {
                    throw saslDigest.mechUnsupportedCharset("UTF-8").toSaslException();
                }
            } else {
                throw saslDigest.mechUnknownCharset().toSaslException();
            }
        }

        if (parsedDigestResponse.get("username") != null) {
            username = new String(parsedDigestResponse.get("username"), clientCharset);
        } else {
            throw saslDigest.mechMissingDirective("username").toSaslException();
        }

        if (parsedDigestResponse.get("realm") != null) {
            realm = new String(parsedDigestResponse.get("realm"), clientCharset);
        } else {
            realm = "";
        }
        if (!arrayContains(realms, realm)) {
            throw saslDigest.mechDisallowedClientRealm(realm).toSaslException();
        }

        if (parsedDigestResponse.get("nonce") == null) {
            throw saslDigest.mechMissingDirective("nonce").toSaslException();
        }

        byte[] nonceFromClient = parsedDigestResponse.get("nonce");
        if (!Arrays.equals(nonce, nonceFromClient)) {
            throw saslDigest.mechNoncesDoNotMatch().toSaslException();
        }

        if (parsedDigestResponse.get("cnonce") == null) {
            throw saslDigest.mechMissingDirective("cnonce").toSaslException();
        }
        cnonce = parsedDigestResponse.get("cnonce");

        if (parsedDigestResponse.get("nc") == null) {
            throw saslDigest.mechMissingDirective("nc").toSaslException();
        }

        if (parsedDigestResponse.get("digest-uri") != null) {
            receivedClientUri = new String(parsedDigestResponse.get("digest-uri"), clientCharset);
            String[] parts = receivedClientUri.split("/", 2);
            String expectedServerName = getServerName();

            if (! digestUriProtocolAccepted.test(parts[0].toLowerCase(Locale.ROOT)) ||
                (expectedServerName != null && ! expectedServerName.toLowerCase(Locale.ROOT).equals(parts[1].toLowerCase(Locale.ROOT)))
               ) {
                throw saslDigest.mechMismatchedWrongDigestUri(receivedClientUri).toSaslException();
            }

            boundServerName = parts[1];
        } else {
            throw saslDigest.mechMissingDirective("digest-uri").toSaslException();
        }

        qop = QOP_AUTH;
        if (parsedDigestResponse.get("qop") != null) {
            qop = new String(parsedDigestResponse.get("qop"), clientCharset);
            if (!arrayContains(QOP_VALUES, qop)) {
                throw saslDigest.mechUnexpectedQop(qop).toSaslException();
            }
            if (qop != null && qop.equals(QOP_AUTH) == false) {
                setWrapper(new DigestWrapper(qop.equals(QOP_AUTH_CONF)));
            }
        }

        byte[] digest_urp = handleUserRealmPasswordCallbacks(null, true, defaultRealm);
        hA1 = H_A1(messageDigest, digest_urp, nonce, cnonce, authorizationId, clientCharset);

        byte[] expectedResponse = digestResponse(messageDigest, hA1, nonce, nonceCount, cnonce, authorizationId, qop, receivedClientUri, true);

        // check response
        if (parsedDigestResponse.get("response") == null) {
            throw saslDigest.mechMissingDirective("response").toSaslException();
        }
        if ( ! Arrays.equals(expectedResponse, parsedDigestResponse.get("response"))) {
            throw saslDigest.mechAuthenticationRejectedInvalidProof().toSaslException();
        }

        createCiphersAndKeys();

        // authorization check
        String authzid = (authorizationId == null || authorizationId.isEmpty()) ? username : authorizationId;
        final AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, authzid);
        try {
            tryHandleCallbacks(authorizeCallback);
        } catch (UnsupportedCallbackException e) {
            throw saslDigest.mechAuthorizationUnsupported(e).toSaslException();
        }
        if (authorizeCallback.isAuthorized()) {
            authorizationId = authorizeCallback.getAuthorizedID();
        } else {
            throw saslDigest.mechAuthorizationFailed(username, authzid).toSaslException();
        }

        return createResponseAuth(parsedDigestResponse);
    }

    private byte[] createResponseAuth(HashMap<String, byte[]> parsedDigestResponse) {
        ByteStringBuilder responseAuth = new ByteStringBuilder();
        responseAuth.append("rspauth=");

        byte[] response_value = digestResponse(messageDigest, hA1, nonce, nonceCount, cnonce, authorizationId, qop, receivedClientUri != null ? receivedClientUri : digestURI, false);

        responseAuth.append(response_value);
        return responseAuth.toArray();
    }

    /* (non-Javadoc)
     * @see javax.security.sasl.SaslServer#getAuthorizationID()
     */
    @Override
    public String getAuthorizationID() {
        return authorizationId;
    }

    /* (non-Javadoc)
     * @see javax.security.sasl.SaslServer#getNegotiatedProperty(String)
     */
    @Override
    public Object getNegotiatedProperty(final String propName) {
        assertComplete();
        if (Sasl.BOUND_SERVER_NAME.equals(propName)) {
            return boundServerName;
        }
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.sasl.util.AbstractSaslParticipant#init()
     */
    @Override
    public void init() {
        setNegotiationState(STEP_ONE);
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        return evaluateMessage(response);
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        switch (state) {
            case STEP_ONE:
                if (message != null && message.length != 0) {
                    throw saslDigest.mechInitialChallengeMustBeEmpty().toSaslException();
                }
                setNegotiationState(STEP_THREE);
                return generateChallenge();
            case STEP_THREE:
                if (message == null || message.length == 0) {
                    throw saslDigest.mechClientRefusesToInitiateAuthentication().toSaslException();
                }

                // parse digest response
                HashMap<String, byte[]> parsedDigestResponse;
                try {
                    parsedDigestResponse = parseResponse(message, charset, false, saslDigest);
                } catch (AuthenticationMechanismException e) {
                    throw e.toSaslException();
                }
                noteDigestResponseData(parsedDigestResponse);

                // validate
                byte[] response = validateDigestResponse(parsedDigestResponse);

                negotiationComplete();
                return response;
        }
        throw Assert.impossibleSwitchCase(state);
    }

}

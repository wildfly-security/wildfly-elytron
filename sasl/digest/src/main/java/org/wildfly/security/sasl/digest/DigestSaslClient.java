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

import static org.wildfly.security.mechanism._private.ElytronMessages.saslDigest;
import static org.wildfly.security.mechanism.digest.DigestUtil.parseResponse;
import static org.wildfly.security.sasl.digest._private.DigestUtil.H_A1;
import static org.wildfly.security.sasl.digest._private.DigestUtil.QOP_AUTH;
import static org.wildfly.security.sasl.digest._private.DigestUtil.QOP_AUTH_CONF;
import static org.wildfly.security.sasl.digest._private.DigestUtil.QOP_VALUES;
import static org.wildfly.security.sasl.digest._private.DigestUtil.convertToHexBytesWithLeftPadding;
import static org.wildfly.security.sasl.digest._private.DigestUtil.digestResponse;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.digest.DigestQuote;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.util.DefaultTransformationMapper;
import org.wildfly.security.util.TransformationMapper;
import org.wildfly.security.util.TransformationSpec;

/**
 * A client implementation of RFC 2831 {@code DIGEST} SASL mechanism.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
final class DigestSaslClient extends AbstractDigestMechanism implements SaslClient {

    private static final byte STEP_TWO = 2;
    private static final byte STEP_FOUR = 4;

    private String[] realms;
    private String[] clientQops;
    private boolean stale = false;
    private int maxbuf = DEFAULT_MAXBUF;
    private String cipher_opts;
    private byte[] digest_urp;

    private final boolean hasInitialResponse;
    private final String[] demandedCiphers;

    DigestSaslClient(String mechanism, String protocol, String serverName, CallbackHandler callbackHandler, String authorizationId, boolean hasInitialResponse, Charset charset, String[] qops, String[] ciphers, Supplier<Provider[]> providers) throws SaslException {
        super(mechanism, protocol, serverName, callbackHandler, FORMAT.CLIENT, charset, ciphers, providers);

        this.hasInitialResponse = hasInitialResponse;
        this.authorizationId = authorizationId;
        this.clientQops = qops == null ? QOP_VALUES : qops;
        this.demandedCiphers = ciphers == null ? new String[] {} : ciphers;
    }

    private void noteChallengeData(HashMap<String, byte[]> parsedChallenge) throws SaslException {
        stale = false;

        LinkedList<String> realmList = new LinkedList<String>();
        for (String keyWord: parsedChallenge.keySet()) {

            if (keyWord.startsWith("realm")) {
                realmList.add(new String(parsedChallenge.get(keyWord), StandardCharsets.UTF_8));
            }
            else if (keyWord.equals("qop")) {
                String serverQops = new String(parsedChallenge.get(keyWord), StandardCharsets.UTF_8);
                this.qop = selectQop(serverQops.split(String.valueOf(DELIMITER)), clientQops);
            }
            else if (keyWord.equals("stale")) {
                stale = Boolean.parseBoolean(new String(parsedChallenge.get(keyWord), StandardCharsets.UTF_8));
            }
            else if (keyWord.equals("maxbuf")) {
                int maxbuf = Integer.parseInt(new String(parsedChallenge.get(keyWord), StandardCharsets.UTF_8));
                if (maxbuf > 0) {
                    this.maxbuf = maxbuf;
                }
            }
            else if (keyWord.equals("nonce")) {
                nonce = parsedChallenge.get(keyWord);
            }
            else if (keyWord.equals("cipher")) {
                cipher_opts = new String(parsedChallenge.get(keyWord), StandardCharsets.UTF_8);
                cipher = selectCipher(cipher_opts);
            }
        }

        if (qop != null && qop.equals(QOP_AUTH) == false) {
            setWrapper(new DigestWrapper(qop.equals(QOP_AUTH_CONF)));
        }

        realms = new String[realmList.size()];
        realmList.toArray(realms);
    }

    private String selectQop(String[] serverQops, String[] clientQops) throws SaslException {
        // select by client preferences
        for(String clientQop : clientQops){
            if (arrayContains(serverQops, clientQop)) {
                return clientQop;
            }
        }
        throw saslDigest.mechNoCommonProtectionLayer().toSaslException();
    }

    private String selectCipher(String ciphersFromServer) throws SaslException {
        if (ciphersFromServer == null) {
            throw saslDigest.mechNoCiphersOfferedByServer().toSaslException();
        }

        TransformationMapper trans = new DefaultTransformationMapper();
        String[] tokensToChooseFrom = ciphersFromServer.split(String.valueOf(DELIMITER));
        for (TransformationSpec ts: trans.getTransformationSpecByStrength(SaslMechanismInformation.Names.DIGEST_MD5, tokensToChooseFrom)) {
            // take the strongest cipher
            for (String c: demandedCiphers) {
                if (c.equals(ts.getToken())) {
                   return ts.getToken();
               }
            }
        }

        throw saslDigest.mechNoCommonCipher().toSaslException();
    }


    /**
     * Method creates client response to the server challenge:
     *
     *    digest-response  = 1#( username | realm | nonce | cnonce |
     *                     nonce-count | qop | digest-uri | response |
     *                     maxbuf | charset | cipher | authzid |
     *                     auth-param )
     *
     *  username         = "username" "=" <"> username-value <">
     *  username-value   = qdstr-val
     *  cnonce           = "cnonce" "=" <"> cnonce-value <">
     *  cnonce-value     = qdstr-val
     *  nonce-count      = "nc" "=" nc-value
     *  nc-value         = 8LHEX
     *  qop              = "qop" "=" qop-value
     *  digest-uri       = "digest-uri" "=" <"> digest-uri-value <">
     *  digest-uri-value  = serv-type "/" host [ "/" serv-name ]
     *  serv-type        = 1*ALPHA
     *  host             = 1*( ALPHA | DIGIT | "-" | "." )
     *  serv-name        = host
     *  response         = "response" "=" response-value
     *  response-value   = 32LHEX
     *  LHEX             = "0" | "1" | "2" | "3" |
     *                     "4" | "5" | "6" | "7" |
     *                     "8" | "9" | "a" | "b" |
     *                     "c" | "d" | "e" | "f"
     *  cipher           = "cipher" "=" cipher-value
     *  authzid          = "authzid" "=" <"> authzid-value <">
     *  authzid-value    = qdstr-val
     *
     * @param parsedChallenge
     * @return
     * @throws SaslException
     */
    private byte[] createResponse(HashMap<String, byte[]> parsedChallenge) throws SaslException {

        ByteStringBuilder digestResponse = new ByteStringBuilder();

        // charset on server
        Charset serverHashedURPUsingcharset;
        byte[] chb = parsedChallenge.get("charset");
        if (chb != null) {
            String chs = new String(chb, StandardCharsets.UTF_8);
            if ("utf-8".equals(chs)) {
                serverHashedURPUsingcharset = StandardCharsets.UTF_8;
            } else {
                serverHashedURPUsingcharset = StandardCharsets.ISO_8859_1;
            }
        } else {
            serverHashedURPUsingcharset = StandardCharsets.ISO_8859_1;
        }

        if (StandardCharsets.UTF_8.equals(serverHashedURPUsingcharset)) {
            digestResponse.append("charset=");
            digestResponse.append("utf-8");
            digestResponse.append(DELIMITER);
        }

        if (! stale || username == null) {
            username = authorizationId; // default username

            if (realms != null && realms.length >= 1) {
                realm = realms[0]; // default realm is first realm from selection
            }

            digest_urp = handleUserRealmPasswordCallbacks(realms, false, false);
        } else {
            saslDigest.trace("Stale nonce - re-authenticating using same credential");
        }

        // username
        digestResponse.append("username=\"");
        digestResponse.append(DigestQuote.quote(username).getBytes(serverHashedURPUsingcharset));
        digestResponse.append("\"").append(DELIMITER);

        // realm
        if(realm != null){
            digestResponse.append("realm=\"");
            digestResponse.append(DigestQuote.quote(realm).getBytes(serverHashedURPUsingcharset));
            digestResponse.append("\"").append(DELIMITER);
        }

        // nonce
        if(nonce == null){
            throw saslDigest.mechMissingDirective("nonce").toSaslException();
        }
        digestResponse.append("nonce=\"");
        digestResponse.append(nonce);
        digestResponse.append("\"").append(DELIMITER);

        // nc | nonce-count
        digestResponse.append("nc=");
        int nonceCount = getNonceCount();
        digestResponse.append(convertToHexBytesWithLeftPadding(nonceCount, 8));
        digestResponse.append(DELIMITER);

        // cnonce
        digestResponse.append("cnonce=\"");
        cnonce = generateNonce();
        digestResponse.append(cnonce);
        digestResponse.append("\"").append(DELIMITER);

        // digest-uri
        digestResponse.append("digest-uri=\"");
        digestResponse.append(digestURI);
        digestResponse.append("\"").append(DELIMITER);

        // maxbuf
        digestResponse.append("maxbuf=");
        digestResponse.append(String.valueOf(maxbuf));
        digestResponse.append(DELIMITER);

        // response
        hA1 = H_A1(messageDigest, digest_urp, nonce, cnonce, authorizationId, serverHashedURPUsingcharset);
        byte[] response_value = digestResponse(messageDigest, hA1, nonce, nonceCount, cnonce, authorizationId, qop, digestURI, true);
        digestResponse.append("response=");
        digestResponse.append(response_value);

        // qop
        digestResponse.append(DELIMITER);
        digestResponse.append("qop=");
        digestResponse.append(qop !=null ? qop : QOP_AUTH);

        // cipher
        if (cipher != null && cipher.length() != 0) {
            digestResponse.append(DELIMITER);
            digestResponse.append("cipher=\"");
            digestResponse.append(cipher);
            digestResponse.append("\"");
        }

        // authzid
        if (authorizationId != null) {
            digestResponse.append(DELIMITER);
            digestResponse.append("authzid=\"");
            digestResponse.append(DigestQuote.quote(authorizationId).getBytes(serverHashedURPUsingcharset));
            digestResponse.append("\"");
        }

        createCiphersAndKeys();

        return digestResponse.toArray();
    }

    /**
     * For now it returns always 1
     * @return
     */
    private int getNonceCount() {
        return 1;
    }

    private void checkResponseAuth(HashMap<String, byte[]> parsedChallenge) throws SaslException {
        byte[] expected = digestResponse(messageDigest, hA1, nonce, getNonceCount(), cnonce, authorizationId, qop, digestURI, false);
        if(!Arrays.equals(expected, parsedChallenge.get("rspauth"))) {
            throw saslDigest.mechServerAuthenticityCannotBeVerified().toSaslException();
        }
    }

    /* (non-Javadoc)
     * @see org.wildfly.sasl.util.AbstractSaslParticipant#init()
     */
    @Override
    public void init() {
        setNegotiationState(STEP_TWO);
    }

    @Override
    public boolean hasInitialResponse() {
        return hasInitialResponse;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        return evaluateMessage(challenge);
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        HashMap<String, byte[]> parsedChallenge;
        try {
            parsedChallenge = parseResponse(message, charset, true, saslDigest);
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        }
        while(true) {
            switch (state) {
                case STEP_TWO:
                    noteChallengeData(parsedChallenge);
                    setNegotiationState(STEP_FOUR);
                    return createResponse(parsedChallenge);
                case STEP_FOUR:
                    if (parsedChallenge.containsKey("nonce")) {
                        saslDigest.trace("Server requested re-authentication");
                        state = STEP_TWO;
                        continue;
                    }
                    checkResponseAuth(parsedChallenge);
                    negotiationComplete();
                    return null;
            }
            throw Assert.impossibleSwitchCase(state);
        }
    }
}

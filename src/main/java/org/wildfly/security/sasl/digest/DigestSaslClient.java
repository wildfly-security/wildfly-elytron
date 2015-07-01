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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.DefaultTransformationMapper;
import org.wildfly.security.util.TransformationMapper;
import org.wildfly.security.util.TransformationSpec;

import static org.wildfly.security.sasl.digest._private.DigestUtil.*;
import static org.wildfly.security._private.ElytronMessages.log;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class DigestSaslClient extends AbstractDigestMechanism implements SaslClient {

    private static final byte STEP_TWO = 2;
    private static final byte STEP_FOUR = 4;

    private String[] realms;
    private String[] clientQops;
    private boolean stale = false;
    private int maxbuf = DEFAULT_MAXBUF;
    private String cipher_opts;

    private final String authorizationId;
    private final boolean hasInitialResponse;
    private final String[] demandedCiphers;
    private final MessageDigest messageDigest;

    DigestSaslClient(String mechanism, String protocol, String serverName, CallbackHandler callbackHandler, String authorizationId, boolean hasInitialResponse, Charset charset, String[] qops, String[] ciphers) throws SaslException {
        super(mechanism, protocol, serverName, callbackHandler, FORMAT.CLIENT, charset, ciphers);

        this.hasInitialResponse = hasInitialResponse;
        this.authorizationId = authorizationId;
        this.clientQops = qops == null ? new String[] {QOP_AUTH} : qops;
        this.demandedCiphers = ciphers == null ? new String[] {} : ciphers;
        try {
            this.messageDigest = MessageDigest.getInstance(messageDigestAlgorithm(mechanism));
        } catch (NoSuchAlgorithmException e) {
            throw log.saslMacAlgorithmNotSupported(getMechanismName(), e);
        }
    }

    private void noteChallengeData(HashMap<String, byte[]> parsedChallenge) throws SaslException {

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
        throw log.saslNoCommonProtectionLayer(getMechanismName());
    }

    private String selectCipher(String ciphersFromServer) throws SaslException {
        if (ciphersFromServer == null) {
            throw log.saslNoCiphersOfferedByServer(getMechanismName());
        }

        TransformationMapper trans = new DefaultTransformationMapper();
        String[] tokensToChooseFrom = ciphersFromServer.split(String.valueOf(DELIMITER));
        for (TransformationSpec ts: trans.getTransformationSpecByStrength(Digest.DIGEST_MD5, tokensToChooseFrom)) {
            // take the strongest cipher
            for (String c: demandedCiphers) {
                if (c.equals(ts.getToken())) {
                   return ts.getToken();
               }
            }
        }

        throw log.saslNoCommonCipher(getMechanismName());
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


        final NameCallback nameCallback;
        if (authorizationId != null) {
            nameCallback = new NameCallback("User name", authorizationId);
        } else {
            nameCallback = new NameCallback("User name");
        }

        final CredentialCallback credentialCallback = new CredentialCallback(DigestPassword.class);
        final PasswordCallback passwordCallback = new PasswordCallback("User password", false);


        String userName = null;
        String realm = null;
        byte[] digestURP;
        try {

            // first try pre-digested credential
            if (realms != null && realms.length > 1) {
                final RealmChoiceCallback realmChoiceCallBack = new RealmChoiceCallback("User realm", realms, 0, false);
                tryHandleCallbacks(realmChoiceCallBack, nameCallback, credentialCallback);
                realm = realms[realmChoiceCallBack.getSelectedIndexes()[0]];
            } else if (realms != null && realms.length == 1) {
                final RealmCallback realmCallback = new RealmCallback("User realm", realms[0]);
                tryHandleCallbacks(realmCallback, nameCallback, credentialCallback);
                realm = realmCallback.getText();
            } else {
                tryHandleCallbacks(nameCallback, credentialCallback);
            }
            userName = nameCallback.getName();
            DigestPassword digestedPassword = (DigestPassword) credentialCallback.getCredential();
            digestURP = digestedPassword.getDigest();

            if(userName == null) throw log.saslCallbackHandlerDoesNotSupportUserName(getMechanismName(), null);
            if(digestURP == null) throw log.saslNotProvidedPreDigested(getMechanismName());

        } catch (UnsupportedCallbackException e) {

            // clear password if pre-digested not supported
            if (e.getCallback() == credentialCallback) {

                if (realms != null && realms.length > 1) {
                    final RealmChoiceCallback realmChoiceCallBack = new RealmChoiceCallback("User realm", realms, 0, false);
                    handleCallbacks(realmChoiceCallBack, nameCallback, passwordCallback);
                    realm = realms[realmChoiceCallBack.getSelectedIndexes()[0]];
                } else if (realms != null && realms.length == 1) {
                    final RealmCallback realmCallback = new RealmCallback("User realm", realms[0]);
                    handleCallbacks(realmCallback, nameCallback, passwordCallback);
                    realm = realmCallback.getText();
                } else {
                    handleCallbacks(nameCallback, passwordCallback);
                }
                userName = nameCallback.getName();
                char[] clearPassword = passwordCallback.getPassword();
                passwordCallback.clearPassword();

                if(userName == null) throw log.saslCallbackHandlerDoesNotSupportUserName(getMechanismName(), null);
                if(clearPassword == null) log.saslNotProvidedClearPassword(getMechanismName());

                digestURP = userRealmPasswordDigest(messageDigest, userName, realm, clearPassword);
                Arrays.fill(clearPassword, (char)0); // wipe out the password

            } else {
                throw log.saslCallbackHandlerFailedForUnknownReason(getMechanismName(), e);
            }

        }


        // username
        digestResponse.append("username=\"");
        digestResponse.append(SaslQuote.quote(userName).getBytes(serverHashedURPUsingcharset));
        digestResponse.append("\"").append(DELIMITER);

        // realm
        if(realm != null){
            digestResponse.append("realm=\"");
            digestResponse.append(SaslQuote.quote(realm).getBytes(serverHashedURPUsingcharset));
            digestResponse.append("\"").append(DELIMITER);
        }

        // nonce
        if(nonce == null){
            throw log.saslMissingDirective(getMechanismName(), "nonce");
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
        hA1 = H_A1(messageDigest, digestURP, nonce, cnonce, authorizationId, serverHashedURPUsingcharset);
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
            digestResponse.append(SaslQuote.quote(authorizationId).getBytes(serverHashedURPUsingcharset));
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
        byte[] expected = digestResponse(messageDigest, hA1, nonce, getNonceCount(), cnonce, authzid, qop, digestURI, false);
        if(!Arrays.equals(expected, parsedChallenge.get("rspauth"))) {
            throw log.saslServerAuthenticityCannotBeVerified(getMechanismName());
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
        HashMap<String, byte[]> parsedChallenge = parseResponse(message);
        switch (state) {
            case STEP_TWO:
                noteChallengeData(parsedChallenge);
                setNegotiationState(STEP_FOUR);
                return createResponse(parsedChallenge);
            case STEP_FOUR:
                checkResponseAuth(parsedChallenge);
                negotiationComplete();
                return null;
        }
        throw Assert.impossibleSwitchCase(state);
    }
}

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

package org.wildfly.security.sasl.md5digest;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.md5digest.AbstractMD5DigestMechanism;
import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.sasl.util.Charsets;
import org.wildfly.security.sasl.util.SaslState;
import org.wildfly.security.sasl.util.SaslStateContext;
import org.wildfly.security.sasl.util.SaslQuote;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class MD5DigestSaslClient extends AbstractMD5DigestMechanism implements SaslClient {


    private static final String DELIMITER = ",";

    private String[] realms;
    private byte[] nonce;
    private String qop;
    private boolean stale = false;
    private int maxbuf = DEFAULT_MAXBUF;
    private String cipher;
    private String cipher_opts;

    private final String authorizationId;
    private final boolean hasInitialResponse;

    private Charset charset = Charsets.LATIN_1;

    /**
     * @param mechanismName
     * @param protocol
     * @param serverName
     * @param callbackHandler
     * @param authorizationId
     * @param hasInitialResponse
     */
    public MD5DigestSaslClient(String mechanism, String protocol, String serverName, CallbackHandler callbackHandler,
            String authorizationId, boolean hasInitialResponse) {
        super(mechanism, protocol, serverName, callbackHandler, FORMAT.CLIENT);

        this.hasInitialResponse = hasInitialResponse;
        this.authorizationId = authorizationId;
    }


    private final SaslState STEP_TWO = new SaslState() {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            HashMap<String, byte[]> parsedChallenge = parseResponse(message);
            noteChallengeData(parsedChallenge);
            getContext().setNegotiationState(STEP_FOUR);
            return createResponse(parsedChallenge);
        }

    };

    private final SaslState STEP_FOUR = new SaslState() {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {

            // TODO: check rspauth

            getContext().setNegotiationState(COMPLETE);
            return null;
        }

    };


    private void noteChallengeData(HashMap<String, byte[]> parsedChallenge) {

        byte[] chb = parsedChallenge.get("charset");
        if (chb != null) {
            String chs = new String(chb);
            if ("utf-8".equals(chs)) {
                charset = Charsets.UTF_8;
            }
        }

        LinkedList<String> realmList = new LinkedList<String>();
        for (String keyWord: parsedChallenge.keySet()) {

            if (keyWord.startsWith("realm")) {
                realmList.add(new String(parsedChallenge.get(keyWord), charset));
            }
            else if (keyWord.equals("qop")) {
                qop = new String(parsedChallenge.get(keyWord), charset);
            }
            else if (keyWord.equals("stale")) {
                stale = Boolean.parseBoolean(new String(parsedChallenge.get(keyWord), charset));
            }
            else if (keyWord.equals("maxbuf")) {
                int maxbuf = Integer.parseInt(new String(parsedChallenge.get(keyWord)));
                if (maxbuf > 0) {
                    this.maxbuf = maxbuf;
                }
            }
            else if (keyWord.equals("nonce")) {
                nonce = parsedChallenge.get(keyWord);
            }
            else if (keyWord.equals("cipher")) {
                cipher_opts = new String(parsedChallenge.get(keyWord), charset);
                selectCipher(cipher_opts);
            }
        }

        realms = new String[realmList.size()];
        realmList.toArray(realms);
    }


    private void selectCipher(String ciphersFromServer) {
        cipher = "";
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

        // charset
        if (Charsets.UTF_8.equals(charset)) {
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

        final PasswordCallback passwordCallback = new PasswordCallback("User password", false);


        String realm = null;
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

        // username
        digestResponse.append("username=\"");
        String userName = nameCallback.getName();
        digestResponse.append(SaslQuote.quote(userName).getBytes(charset));
        digestResponse.append("\"").append(DELIMITER);

        // realm
        if(realm != null){
            digestResponse.append("realm=\"");
            digestResponse.append(SaslQuote.quote(realm).getBytes(charset));
            digestResponse.append("\"").append(DELIMITER);
        }

        // nonce
        if(nonce == null){
            throw new SaslException("Nonce not provided by server");
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
        byte[] cnonce = generateNonce();
        digestResponse.append(cnonce);
        digestResponse.append("\"").append(DELIMITER);

        // digest-uri
        digestResponse.append("digest-uri=\"");
        digestResponse.append(digestURI);
        digestResponse.append("\"").append(DELIMITER);

        // maxbuf
        //if (maxbuf != DEFAULT_MAXBUF) {
            digestResponse.append("maxbuf=");
            digestResponse.append(String.valueOf(maxbuf));
            digestResponse.append(DELIMITER);
        //}

        // response
        char[] passwd = null;
        byte[] response_value;
        try {
            passwd = passwordCallback.getPassword();
            passwordCallback.clearPassword();
            response_value = digestResponse(userName, realm, passwd, nonce, nonceCount, cnonce, authorizationId, qop, digestURI);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("Algorithm not supported", e);
        } finally {
            // wipe out the password
            if (passwd != null) {
                Arrays.fill(passwd, (char)0);
            }
        }
        digestResponse.append("response=");
        digestResponse.append(response_value);

        // qop
        digestResponse.append(DELIMITER);
        digestResponse.append("qop=");
        digestResponse.append(qop!=null ? qop : "auth");

        // cipher
        if (cipher != null && cipher.length() != 0) {
            digestResponse.append(DELIMITER);
            digestResponse.append("cipher=");
            digestResponse.append(cipher);
            digestResponse.append(DELIMITER);
        }

        // authzid
        if (authorizationId != null) {
            digestResponse.append(DELIMITER);
            digestResponse.append("authzid=\"");
            digestResponse.append(SaslQuote.quote(authorizationId).getBytes(Charsets.UTF_8));
            digestResponse.append("\"");
        }

        return digestResponse.toArray();
    }

    /**
     * For now it returns always 1
     * @return
     */
    private int getNonceCount() {
        return 1;
    }

    /* (non-Javadoc)
     * @see org.wildfly.sasl.util.AbstractSaslParticipant#init()
     */
    @Override
    public void init() {
        getContext().setNegotiationState(STEP_TWO);
    }

    @Override
    public boolean hasInitialResponse() {
        return hasInitialResponse;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        return evaluateMessage(challenge);
    }

}

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

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

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
public class MD5DigestSaslServer extends AbstractMD5DigestMechanism implements SaslServer {
    
    public MD5DigestSaslServer(String[] realms, String mechanismName, String protocol, String serverName,
            CallbackHandler callbackHandler, String charsetName) {
        super(mechanismName, protocol, serverName, callbackHandler, FORMAT.SERVER);
        this.realms = realms;
        this.supportedCiphers = getSupportedCiphers();
        if (charsetName != null && charsetName.equalsIgnoreCase("UTF-8")) {
            // there are only two possibilities 8859_1 or UTF-8 (the 8859_1 is default)
            this.charset = Charsets.UTF_8;
        }
        
    }

    public static final String[] CIPHER_OPTS = {"des", "3des", "rc4", "rc4-40", "rc4-56"};

    private static final String DELIMITER = ",";
    
    public static final String[] DEFAULT_CIPHER_NAMES = { 
        "DESede/CBC/NoPadding",
        "RC4",
        "DES/CBC/NoPadding"   
    };

    private String[] realms;
    private String configuredQops;
    private String supportedCiphers;
    private Charset charset = Charsets.LATIN_1; // 8859_1 is default
    private int receivingMaxBuffSize;
    private String qops;
    private String authorizationId;
    private int nonceCount = -1;
    private byte[] nonce = null;
    
    private final SaslState STEP_ONE = new SaslState() {
        
        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
    
            if (message.length != 0) {
                throw new SaslException(getMechanismName() + ": When sending challenge message has to be empty.");
            }
            getContext().setNegotiationState(STEP_THREE);
            return generateChallenge();
        }
    };

    
    private final SaslState STEP_THREE = new SaslState() {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            
            if (message == null || message.length == 0) {
                throw new SaslException(getMechanismName() + ": message cannot be empty nor null");
            }
            
            // parse digest response
            HashMap<String, byte[]> parsedDigestResponse = parseResponse(message);
            noteDigestResponseData(parsedDigestResponse);
         
            // validate
            byte[] response = validateDigestResponse(parsedDigestResponse);

            getContext().setNegotiationState(SaslState.COMPLETE);
            return response;
        }
        
    };

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
            sb.append("realm=\"").append(SaslQuote.quote(realm)).append("\"").append(DELIMITER);
        }
        challenge.append(sb.toString().getBytes(charset));
        
        
        // nonce
        challenge.append("nonce=\"");
        challenge.append(SaslQuote.quote(generateNonce()));
        challenge.append("\"").append(DELIMITER);
        
        // qop
        if (qops != null) {
            challenge.append("qop=\"");
            challenge.append(SaslQuote.quote(qops).getBytes(charset));
            challenge.append("\"").append(DELIMITER);
        }
        
        // maxbuf
        if (receivingMaxBuffSize != DEFAULT_MAXBUF) {
            challenge.append("maxbuf=");
            challenge.append(String.valueOf(receivingMaxBuffSize));
            challenge.append(DELIMITER);
        }
        
        // charset
        if (Charsets.UTF_8.equals(charset)) {
            challenge.append("charset=\"");
            challenge.append("utf-8");
            challenge.append("\"").append(DELIMITER);
        }
        
        // cipher
        if (supportedCiphers != null) {
            challenge.append("cipher=\"");
            challenge.append(SaslQuote.quote(supportedCiphers).getBytes(charset));
            challenge.append("\"").append(DELIMITER);
        }
        
        return challenge.toArray();
    }

    private void noteDigestResponseData(HashMap<String, byte[]> parsedDigestResponse) {
        
        byte[] data = parsedDigestResponse.get("nonce");
        if (data != null) {
            nonce = data.clone();
        } else {
            nonce = null;
        }
        
        data = parsedDigestResponse.get("nonce-count");
        if (data != null) {
            nonceCount = Integer.valueOf(new String(data));
        } else {
            nonceCount = -1;
        }

    }
    
    private byte[] validateDigestResponse(HashMap<String, byte[]> parsedDigestResponse) throws SaslException {
        if (nonceCount != 1) {
            throw new SaslException(getMechanismName() + ": nonce-count is not equal to 1");
        }
        
        Charset clientCharset = Charsets.LATIN_1;
        if (parsedDigestResponse.get("charset") != null) {
            String cCharset = new String(parsedDigestResponse.get("charset"), charset);
            if (Charsets.UTF_8.equals(charset) && cCharset.equals("utf-8")) {
                clientCharset = Charsets.UTF_8;
            } else {
                throw new SaslException(getMechanismName() + ": client charset should not be specified as server is using iso 8859-1");
            }
        }
        
        String userName;
        if (parsedDigestResponse.get("username") != null) {
            userName = new String(parsedDigestResponse.get("username"), clientCharset);
        } else {
            throw new SaslException(getMechanismName() + ": missing username directive");
        }
        
        String clientRealm;
        if (parsedDigestResponse.get("realm") != null) {
            clientRealm = new String(parsedDigestResponse.get("realm"), clientCharset);
        } else {
            clientRealm = "";
        }
        if (!serverContainsRealm(clientRealm)) {
            throw new SaslException(getMechanismName() + ": client sent realm not present at the server (" + clientRealm + ")");
        }
        
        if (parsedDigestResponse.get("nonce") == null) {
            throw new SaslException(getMechanismName() + ": missing nonce");
        }
        
        byte[] nonceFromClient = parsedDigestResponse.get("nonce");
        if (!Arrays.equals(nonce, nonceFromClient)) {
            throw new SaslException(getMechanismName() + ": nonce mismatch");
        }
        
        if (parsedDigestResponse.get("cnonce") == null) {
            throw new SaslException(getMechanismName() + ": missing cnonce");
        }
        byte[] cnonce = parsedDigestResponse.get("cnonce");
        
        if (parsedDigestResponse.get("nonce-count") == null) {
            throw new SaslException(getMechanismName() + ": missing nonce-count");
        }
        
        String digest_uri;
        if (parsedDigestResponse.get("digest-uri") != null) {
            digest_uri = new String(parsedDigestResponse.get("digest-uri"), clientCharset);
            if (!digest_uri.equalsIgnoreCase(digestURI)) {
                throw new SaslException(getMechanismName() + ": mismatched digest-uri " + digest_uri + ". Expected: " + digestURI);
            }
        } else {
            throw new SaslException(getMechanismName() + ": digest-uri directive is missing");
        }

        String qop;
        if (parsedDigestResponse.get("qop") != null) {
            qop = new String(parsedDigestResponse.get("qop"), clientCharset);
            if (!qop.equals("auth") && !qop.equals("auth-int") && !qop.equals("auth-conf")) {
                throw new SaslException(getMechanismName() + ": qop directive unexpected value " + qop);
            }
        } else {
            qop = "auth";
        }
        
        
        // get password
        final NameCallback nameCallback = new NameCallback("User name", userName);
        final PasswordCallback passwordCallback = new PasswordCallback("User password", false);
        final RealmCallback realmCallback = new RealmCallback("User realm");

        handleCallbacks(realmCallback, nameCallback, passwordCallback);
        
        char[] passwd = null;
        byte[] expectedResponse;
        try {
            passwd = passwordCallback.getPassword();
            passwordCallback.clearPassword();
            expectedResponse = digestResponse(userName, clientRealm, passwd, 
                    nonce, nonceCount, cnonce, 
                    new String(parsedDigestResponse.get("authzid"), clientCharset), qop, digestURI);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("Algorithm not supported", e);
        } finally {
            // wipe out the password
            if (passwd != null) {
                Arrays.fill(passwd, (char)0);
            }
        }
        
        if (parsedDigestResponse.get("response") != null) {
            if (Arrays.equals(expectedResponse, parsedDigestResponse.get("response"))) {
                this.authorizationId = new String(parsedDigestResponse.get("authzid"), clientCharset);
                return new byte[0];
            } else {
                throw new SaslException(getMechanismName() + ": authentication failed");
            }
            
        } else {
            throw new SaslException(getMechanismName() + ": missing response directive");
        }
        
    }
    
    private boolean serverContainsRealm(String realm) {
        for (String r: realms) {
            if (realm.equals(r)) {
                return true;
            }
        }
        return false;
    }
    
    private byte[] createResponseAuth(HashMap<String, byte[]> parsedDigestResponse) {
        ByteStringBuilder responseAuth = new ByteStringBuilder();
        responseAuth.append("rspauth=");
        
        // TODO
        byte[] response_value = null;
        
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
     * @see org.wildfly.sasl.util.AbstractSaslParticipant#init()
     */
    @Override
    public void init() {
        getContext().setNegotiationState(STEP_ONE);
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        return evaluateMessage(response);
    }

    
}

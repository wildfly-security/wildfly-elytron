/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.sasl.localuser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.sasl.util.AbstractSaslServer;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class LocalUserServer extends AbstractSaslServer implements SaslServer {

    // Should SecureRandom be used? Default to true
    public static final String LOCAL_USER_USE_SECURE_RANDOM = "wildfly.sasl.local-user.use-secure-random";
    public static final String LEGACY_LOCAL_USER_USE_SECURE_RANDOM = "jboss.sasl.local-user.use-secure-random";
    public static final String LOCAL_USER_CHALLENGE_PATH = "wildfly.sasl.local-user.challenge-path";
    public static final String LEGACY_LOCAL_USER_CHALLENGE_PATH = "jboss.sasl.local-user.challenge-path";
    public static final String DEFAULT_USER = "wildfly.sasl.local-user.default-user";
    public static final String LEGACY_DEFAULT_USER = "jboss.sasl.local-user.default-user";

    private static final byte UTF8NUL = 0x00;

    private volatile String authorizationId;
    private volatile File challengeFile;
    private final File basePath;
    private final String defaultUser;
    private final boolean useSecureRandom;

    LocalUserServer(final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler callbackHandler) {
        super(LocalUserSaslFactory.JBOSS_LOCAL_USER, protocol, serverName, callbackHandler);
        String value;
        if (props.containsKey(LOCAL_USER_CHALLENGE_PATH)) {
            basePath = new File(props.get(LOCAL_USER_CHALLENGE_PATH).toString()).getAbsoluteFile();
        } else if (props.containsKey(LEGACY_LOCAL_USER_CHALLENGE_PATH)) {
            basePath = new File(props.get(LEGACY_LOCAL_USER_CHALLENGE_PATH).toString()).getAbsoluteFile();
        } else if ((value = getProperty(LOCAL_USER_CHALLENGE_PATH)) != null) {
            basePath = new File(value).getAbsoluteFile();
        } else if ((value = getProperty(LEGACY_LOCAL_USER_CHALLENGE_PATH)) != null) {
            basePath = new File(value).getAbsoluteFile();
        } else {
            basePath = new File(getProperty("java.io.tmpdir"));
        }

        Object useSecureRandomObj = null;
        if (props.containsKey(LOCAL_USER_USE_SECURE_RANDOM)) {
            useSecureRandomObj = props.get(LOCAL_USER_USE_SECURE_RANDOM);
        } else if (props.containsKey(LEGACY_LOCAL_USER_USE_SECURE_RANDOM)) {
            useSecureRandomObj = props.get(LEGACY_LOCAL_USER_USE_SECURE_RANDOM);
        } else {
            useSecureRandomObj = getProperty(LOCAL_USER_USE_SECURE_RANDOM);
            if (useSecureRandomObj == null) {
                useSecureRandomObj = getProperty(LEGACY_LOCAL_USER_USE_SECURE_RANDOM);
            }
        }

        if (useSecureRandomObj != null) {
            if (useSecureRandomObj instanceof Boolean) {
                useSecureRandom = ((Boolean) useSecureRandomObj).booleanValue();
            } else if (useSecureRandomObj instanceof String) {
                useSecureRandom = Boolean.parseBoolean((String) useSecureRandomObj);
            } else {
                useSecureRandom = true;
            }
        } else {
            useSecureRandom = true;
        }

        if (props.containsKey(DEFAULT_USER)) {
            defaultUser = (String) props.get(DEFAULT_USER);
        } else if (props.containsKey(LEGACY_DEFAULT_USER)) {
            defaultUser = (String) props.get(LEGACY_DEFAULT_USER);
        } else {
            defaultUser = null;
        }
    }

    private static String getProperty(final String name) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty(name);
                }
            });
        } else {
            return System.getProperty(name);
        }
    }

    private Random getRandom() {
        if (useSecureRandom) {
            return new SecureRandom();
        } else {
            return new Random();
        }
    }

    public void init() {
        getContext().setNegotiationState(new SaslState() {
            public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                if (message.length == 0) {
                    // trigger initial response
                    return NO_BYTES;
                }

                // initial message
                if (message.length == 1 && message[0] == UTF8NUL) {
                    authorizationId = null;
                } else {
                    authorizationId = new String(message, Charsets.UTF_8);
                }
                final Random random = getRandom();
                try {
                    challengeFile = File.createTempFile("local", ".challenge", basePath);
                } catch (IOException e) {
                    throw new SaslException("Failed to create challenge file", e);
                }

                final FileOutputStream fos;
                try {
                    fos = new FileOutputStream(challengeFile);
                } catch (FileNotFoundException e) {
                    throw new SaslException("Failed to create challenge file", e);
                }
                boolean ok = false;
                final byte[] bytes;
                try {
                    bytes = new byte[8];
                    random.nextBytes(bytes);
                    try {
                        fos.write(bytes);
                        fos.close();
                        ok = true;
                    } catch (IOException e) {
                        throw new SaslException("Failed to create challenge file", e);
                    }
                } finally {
                    if (!ok) {
                        deleteChallenge();
                    }
                    try {
                        fos.close();
                    } catch (Throwable ignored) {
                    }
                }
                final String path = challengeFile.getAbsolutePath();
                final byte[] response = new byte[Charsets.encodedLengthOf(path)];
                Charsets.encodeTo(path, response, 0);
                getContext().setNegotiationState(new SaslState() {
                    public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                        deleteChallenge();
                        final int length = message.length;
                        if (length < 8) {
                            throw new SaslException("Invalid response");
                        }
                        if (!Arrays.equals(bytes, Arrays.copyOf(message, 8))) {
                            throw new SaslException("Invalid response");
                        }
                        String authenticationRealm;
                        String authenticationId;
                        final int firstMarker = Charsets.indexOf(message, 0, 8);
                        if (firstMarker > -1) {
                            authenticationId = new String(message, 8, firstMarker - 8, Charsets.UTF_8);
                            final int secondMarker = Charsets.indexOf(message, 0, firstMarker + 1);
                            if (secondMarker > -1) {
                                authenticationRealm = new String(message, firstMarker + 1, secondMarker - firstMarker - 1, Charsets.UTF_8);
                            } else {
                                authenticationRealm = null;
                            }
                        } else {
                            authenticationId = null;
                            authenticationRealm = null;
                        }
                        if (authenticationId == null || authenticationId.length() == 0) {
                            authenticationId = defaultUser;
                        }
                        if (authenticationId == null) {
                            throw new SaslException("No authentication ID given");
                        }
                        if (authorizationId == null) {
                            // If no authorization ID is specifed default to authentication ID
                            authorizationId = authenticationId;
                        }
                        final NameCallback nameCallback = new NameCallback("User name", authenticationId);
                        final AuthorizeCallback authorizeCallback = new AuthorizeCallback(authenticationId, authorizationId);
                        if (authenticationRealm == null) {
                            handleCallbacks(nameCallback, authorizeCallback);
                        } else {
                            final RealmCallback realmCallback = new RealmCallback("User realm", authenticationRealm);
                            handleCallbacks(realmCallback, nameCallback, authorizeCallback);
                        }
                        if (!authorizeCallback.isAuthorized()) {
                            throw new SaslException("User " + authorizationId + " is not authorized");
                        }
                        context.negotiationComplete();
                        return null;
                    }
                });
                return response;
            }
        });
    }

    public String getAuthorizationID() {
        if (isComplete()) {
            return authorizationId;
        } else {
            throw new IllegalStateException("JBOSS-LOCAL-USER server negotiation not complete");
        }
    }

    private void deleteChallenge() {
        if (challengeFile != null) {
            challengeFile.delete();
            challengeFile = null;
        }
    }

    @Override
    public void dispose() throws SaslException {
        super.dispose();
        deleteChallenge();
    }

    @Override
    protected void finalize() throws Throwable {
        deleteChallenge();
    }
}

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

package org.jboss.sasl.localuser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import org.jboss.sasl.util.AbstractSaslServer;
import org.jboss.sasl.util.Charsets;
import org.jboss.sasl.util.SaslState;
import org.jboss.sasl.util.SaslStateContext;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class LocalUserServer extends AbstractSaslServer implements SaslServer {

    public static final String LOCAL_USER_CHALLENGE_PATH = "jboss.sasl.local-user.challenge-path";

    private volatile String authorizationId;
    private final File basePath;

    LocalUserServer(final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler callbackHandler) {
        super(LocalUserSaslFactory.JBOSS_LOCAL_USER, protocol, serverName, callbackHandler);
        String value;
        if (props.containsKey(LOCAL_USER_CHALLENGE_PATH)) {
            basePath = new File(props.get(LOCAL_USER_CHALLENGE_PATH).toString()).getAbsoluteFile();
        } else if ((value = getProperty(LOCAL_USER_CHALLENGE_PATH)) != null) {
            basePath = new File(value).getAbsoluteFile();
        } else {
            basePath = new File(getProperty("java.io.tmpdir"));
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

    public void init() {
        getContext().setNegotiationState(new SaslState() {
            public byte[] evaluateMessage(final SaslStateContext context, final byte[] message) throws SaslException {
                // initial message
                authorizationId = message.length > 0 ? new String(message, Charsets.UTF_8) : null;
                final Random random = new Random();
                File testFile;
                do {
                    testFile = new File(basePath, "challenge-" + (random.nextInt(8999999) + 1000000));
                } while (testFile.exists());
                final File challengeFile = testFile;
                final FileOutputStream fos;
                try {
                    challengeFile.delete();
                    fos = new FileOutputStream(testFile);
                    challengeFile.deleteOnExit();
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
                        challengeFile.delete();
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
                        challengeFile.delete();
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
                        if (authenticationId == null) {
                            throw new SaslException("No authentication ID given");
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
        return authorizationId;
    }
}

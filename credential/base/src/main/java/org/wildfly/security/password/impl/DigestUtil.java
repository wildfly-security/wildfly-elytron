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
package org.wildfly.security.password.impl;

import static org.wildfly.security.credential._private.ElytronMessages.log;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.function.Supplier;

import javax.security.sasl.SaslException;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.credential._private.ElytronMessages;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Common utility functions used by Digest authentication mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
class DigestUtil {

    public static byte[] userRealmPasswordDigest(MessageDigest messageDigest, String username, String realm, char[] password) {
        CharsetEncoder latin1Encoder = StandardCharsets.ISO_8859_1.newEncoder();
        latin1Encoder.reset();
        boolean bothLatin1 = latin1Encoder.canEncode(username);
        latin1Encoder.reset();
        if (bothLatin1) {
            for (char c: password) {
                bothLatin1 = bothLatin1 && latin1Encoder.canEncode(c);
            }
        }

        Charset chosenCharset = StandardCharsets.UTF_8; // bothLatin1 ? StandardCharsets.ISO_8859_1 : StandardCharsets.UTF_8;

        ByteStringBuilder urp = new ByteStringBuilder(); // username:realm:password
        urp.append(username.getBytes(chosenCharset));
        urp.append(':');
        if (realm != null) {
            urp.append(realm.getBytes((chosenCharset)));
        } else {
            urp.append("");
        }
        urp.append(':');
        urp.append(new String(password).getBytes((chosenCharset)));

        return messageDigest.digest(urp.toArray());
    }

}

package org.wildfly.security.auth.provider.ldap;

import java.nio.charset.Charset;
import java.security.MessageDigest;

import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.util.Base64;
import org.wildfly.security.util.ByteArrayIterator;

public class Temp {

    static final Charset UTF_8 = Charset.forName("UTF-8");

    public static void main(String[] args) throws Exception {
        for (CredentialSupport outer : CredentialSupport.values()) {
            for (CredentialSupport inner : CredentialSupport.values()) {
                System.out.println(String.format("%s.compareTo(%s)=%d", outer, inner, outer.compareTo(inner)));
            }
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] response = digest.digest("xxxx".getBytes(UTF_8));

        StringBuilder builder = new StringBuilder();
        Base64.base64EncodeB(builder, new ByteArrayIterator(response));

        System.out.println(builder.toString());
    }

}

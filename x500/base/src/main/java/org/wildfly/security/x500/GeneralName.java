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

package org.wildfly.security.x500;

import static org.wildfly.security.x500._private.ElytronMessages.log;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;

/**
 * A representation of an X.509 general name.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public abstract class GeneralName implements ASN1Encodable {

    // General name types
    public static final int OTHER_NAME = 0;
    public static final int RFC_822_NAME = 1;
    public static final int DNS_NAME = 2;
    public static final int X400_ADDRESS = 3;
    public static final int DIRECTORY_NAME = 4;
    public static final int EDI_PARTY_NAME = 5;
    public static final int URI_NAME = 6;
    public static final int IP_ADDRESS = 7;
    public static final int REGISTERED_ID = 8;

    private final int type;

    GeneralName(final int type) {
        if (type < 0 || type > 8) {
            throw log.invalidValueForGeneralNameType();
        }
        this.type = type;
    }

    /**
     * Get the type of this general name.
     *
     * @return the type of this general name
     */
    public int getType() {
        return type;
    }

    /**
     * Get the name.
     *
     * @return the name
     */
    public abstract Object getName();

    /**
     * <p>
     * Encode this {@code GeneralName} element using the given ASN.1 encoder,
     * where {@code GeneralName} is defined as:
     *
     * <pre>
     *      GeneralName ::= CHOICE {
     *          otherName                       [0]     OtherName,
     *          rfc822Name                      [1]     IA5String,
     *          dNSName                         [2]     IA5String,
     *          x400Address                     [3]     ORAddress,
     *          directoryName                   [4]     Name,
     *          ediPartyName                    [5]     EDIPartyName,
     *          uniformResourceIdentifier       [6]     IA5String,
     *          iPAddress                       [7]     OCTET STRING,
     *          registeredID                    [8]     OBJECT IDENTIFIER
     *      }
     * </pre>
     * </p>
     *
     * @param encoder the encoder (must not be {@code null})
     * @throws ASN1Exception if the general name is invalid
     */
    public abstract void encodeTo(ASN1Encoder encoder);

    /**
     * A generic name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class OtherName extends GeneralName {

        private final byte[] encodedName;
        private final String typeId;
        private final byte[] encodedValue;

        /**
         * <p>
         * Create an {@code OtherName} that is defined as:
         *
         * <pre>
         *      OtherName ::= SEQUENCE {
         *                      type-id    OBJECT IDENTIFIER,
         *                      value      [0] EXPLICIT ANY DEFINED BY type-id }
         * </pre>
         * </p>
         *
         * @param encodedName the DER encoded form of the name, as a byte array
         * @throws ASN1Exception if {@code encodedName} is not DER encoded
         */
        public OtherName(final byte[] encodedName) throws ASN1Exception {
            super(OTHER_NAME);
            this.encodedName = encodedName;
            final DERDecoder decoder = new DERDecoder(encodedName);
            decoder.startSequence();
            typeId = decoder.decodeObjectIdentifier();
            encodedValue = decoder.drainElement();
            decoder.endSequence();
        }

        /**
         * <p>
         * Create an {@code OtherName} that is defined as:
         *
         * <pre>
         *      OtherName ::= SEQUENCE {
         *                      type-id    OBJECT IDENTIFIER,
         *                      value      [0] EXPLICIT ANY DEFINED BY type-id }
         * </pre>
         * </p>
         *
         * @param typeId the object identifier for this name
         * @param encodedValue the DER encoded value for this name
         * @throws ASN1Exception if {@code encodedValue} is not DER encoded
         */
        public OtherName(final String typeId, final byte[] encodedValue) throws ASN1Exception {
            super(OTHER_NAME);
            this.typeId = typeId;
            this.encodedValue = encodedValue;
            final DEREncoder encoder = new DEREncoder();
            encoder.startSequence();
            encoder.encodeObjectIdentifier(typeId);
            encoder.writeEncoded(encodedValue);
            encoder.endSequence();
            encodedName = encoder.getEncoded();
        }

        public byte[] getName() {
            return encodedName.clone();
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.startSequence();
            encoder.encodeObjectIdentifier(getObjectIdentifier());
            encoder.writeEncoded(getEncodedValue());
            encoder.endSequence();
        }

        public String getObjectIdentifier() {
            return typeId;
        }

        public byte[] getEncodedValue() {
            return encodedValue.clone();
        }

        public boolean equals(final Object obj) {
            return obj instanceof OtherName && equals((OtherName) obj);
        }

        public boolean equals(final OtherName other) {
            return other != null && MessageDigest.isEqual(encodedName, other.getName());
        }

        public int hashCode() {
            return Arrays.hashCode(encodedName);
        }
    }

    /**
     * An RFC 822 name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class RFC822Name extends GeneralName {

        private final String name;

        /**
         * Create an RFC 822 name.
         *
         * @param name the RFC 822 name, as a {@code String}
         */
        public RFC822Name(final String name) {
            super(RFC_822_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.encodeIA5String(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof RFC822Name && equals((RFC822Name) obj);
        }

        public boolean equals(final RFC822Name other) {
            return other != null && name.equalsIgnoreCase(other.getName());
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * A DNS name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class DNSName extends GeneralName {

        private final String name;

        /**
         * Create a DNS name.
         *
         * @param name the DNS name, as a {@code String}
         */
        public DNSName(final String name) {
            super(DNS_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.encodeIA5String(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof DNSName && equals((DNSName) obj);
        }

        public boolean equals(final DNSName other) {
            return other != null && name.equalsIgnoreCase(other.getName());
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * An X.400 address.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class X400Address extends GeneralName {

        private final byte[] encodedName;

        /**
         * <p>
         * Create an {@code X400Address} that is defined as:
         *
         * <pre>
         *      X400Address ::= SEQUENCE {
         *                          built-in-standard-attributes        BuiltInStandardAttributes,
         *                          built-in-domain-defined-attributes  BuiltInDomainDefinedAttributes OPTIONAL,
         *                          -- see also teletex-domain-defined-attributes
         *                          extension-attributes                ExtensionAttributes OPTIONAL    }
         * </pre>
         * </p>
         *
         * @param encodedName the DER encoded form of the name, as a byte array
         * @throws ASN1Exception if {@code encodedName} is not DER encoded
         */
        public X400Address(final byte[] encodedName) throws ASN1Exception {
            this(encodedName, false);
        }

        /**
         * <p>
         * Create an {@code X400Address} that is defined as:
         *
         * <pre>
         *      X400Address ::= SEQUENCE {
         *                          built-in-standard-attributes        BuiltInStandardAttributes,
         *                          built-in-domain-defined-attributes  BuiltInDomainDefinedAttributes OPTIONAL,
         *                          -- see also teletex-domain-defined-attributes
         *                          extension-attributes                ExtensionAttributes OPTIONAL    }
         * </pre>
         * </p>
         *
         * @param encoded the DER encoded form of the name or the value bytes from the DER encoded form of the name, as a byte array
         * @param valueBytesOnly whether or not {@code encoded} contains only the value bytes from the DER encoded form of the name
         * @throws ASN1Exception if {@code encoded} is not DER encoded
         */
        public X400Address(final byte[] encoded, final boolean valueBytesOnly) throws ASN1Exception {
            super(X400_ADDRESS);
            if (valueBytesOnly) {
                final DEREncoder encoder = new DEREncoder();
                encoder.startSequence();
                encoder.writeEncoded(encoded);
                encoder.endSequence();
                encodedName = encoder.getEncoded();
            } else {
                encodedName = encoded;
            }
        }

        public byte[] getName() {
            return encodedName.clone();
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.writeEncoded(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof X400Address && equals((X400Address) obj);
        }

        public boolean equals(final X400Address other) {
            return other != null && MessageDigest.isEqual(encodedName, other.getName());
        }

        public int hashCode() {
            return Arrays.hashCode(encodedName);
        }
    }

    /**
     * A directory name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class DirectoryName extends GeneralName {

        private final String name;

        /**
         * Create a directory name.
         *
         * @param name the directory name, as a {@code String}
         */
        public DirectoryName(final String name) {
            super(DIRECTORY_NAME);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.startExplicit(getType());
            encoder.writeEncoded(new X500Principal(getName()).getEncoded());
            encoder.endExplicit();
        }

        public boolean equals(final Object obj) {
            return obj instanceof DirectoryName && equals((DirectoryName) obj);
        }

        public boolean equals(final DirectoryName other) {
            return (new X500Principal(name)).equals(new X500Principal(other.getName()));
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * An EDI party name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class EDIPartyName extends GeneralName {

        private final byte[] encodedName;

        /**
         * <p>
         * Create an {@code EDIPartyName} that is defined as:
         *
         * <pre>
         *      EDIPartyName ::= SEQUENCE {
         *                          nameAssigner        [0]     DirectoryString OPTIONAL,
         *                          partyName           [1]     DirectoryString }
         * </pre>
         * </p>
         *
         * @param encodedName the DER encoded form of the name, as a byte array
         * @throws ASN1Exception if {@code encodedName} is not DER encoded
         */
        public EDIPartyName(final byte[] encodedName) throws ASN1Exception {
            this(encodedName, false);
        }

        /**
         * <p>
         * Create an {@code EDIPartyName} that is defined as:
         *
         * <pre>
         *      EDIPartyName ::= SEQUENCE {
         *                          nameAssigner        [0]     DirectoryString OPTIONAL,
         *                          partyName           [1]     DirectoryString }
         * </pre>
         * </p>
         *
         * @param encoded the DER encoded form of the name or the value bytes from the DER encoded form of the name, as a byte array
         * @param valueBytesOnly whether or not {@code encoded} contains only the value bytes from the DER encoded form of the name
         * @throws ASN1Exception if {@code encoded} is not DER encoded
         */
        public EDIPartyName(final byte[] encoded, final boolean valueBytesOnly) throws ASN1Exception {
            super(EDI_PARTY_NAME);
            if (valueBytesOnly) {
                final DEREncoder encoder = new DEREncoder();
                encoder.startSequence();
                encoder.writeEncoded(encoded);
                encoder.endSequence();
                encodedName = encoder.getEncoded();
            } else {
                encodedName = encoded;
            }
        }

        public byte[] getName() {
            return encodedName.clone();
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.writeEncoded(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof EDIPartyName && equals((EDIPartyName) obj);
        }

        public boolean equals(final EDIPartyName other) {
            return other != null && MessageDigest.isEqual(encodedName, other.getName());
        }

        public int hashCode() {
            return Arrays.hashCode(encodedName);
        }
    }

    /**
     * A URI name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class URIName extends GeneralName {

        private final String name;

        /**
         * Create a URI name.
         *
         * @param name the URI name, as a {@code String}
         */
        public URIName(final String name) {
            super(URI_NAME);
            try {
                if (! (new URI(name).isAbsolute())) {
                    throw log.asnInvalidGeneralNameForUriTypeMissingScheme();
                }
            } catch (URISyntaxException e) {
                throw log.asnInvalidGeneralNameForUriType(e);
            }
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.encodeIA5String(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof URIName && equals((URIName) obj);
        }

        public boolean equals(final URIName other) {
            try {
                return (new URI(name)).equals(new URI(other.getName()));
            } catch (URISyntaxException e) {
                throw log.asnInvalidGeneralNameForUriType(e);
            }
        }

        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * An IP address.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class IPAddress extends GeneralName {

        private final byte[] address;

        /**
         * Create an IP address.
         *
         * @param strAddress the IP address, as a {@code String}
         */
        public IPAddress(final String strAddress) {
            this(parseIPAddress(strAddress));
        }

        /**
         * Create an IP address.
         *
         * @param address the IP address, as a byte array
         */
        public IPAddress(final byte[] address) {
            super(IP_ADDRESS);
            if ((address.length != 4) && (address.length != 8) && (address.length != 16) && (address.length != 32)) {
                throw log.asnInvalidGeneralNameForIpAddressType();
            }
            this.address = address;
        }

        public byte[] getName() {
            return address;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.encodeOctetString(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof IPAddress && equals((IPAddress) obj);
        }

        public boolean equals(final IPAddress other) {
            if (other != null) {
                byte[] otherAddress = other.getName();
                int length = address.length;
                int otherLength = otherAddress.length;
                if (length != otherLength) {
                    return false;
                }
                if ((length == 8) || (length == 32)) {
                    int maskLength = length / 2;
                    byte maskedByte;
                    byte otherMaskedByte;
                    // Compare masked values
                    for (int i = 0; i < maskLength; i++) {
                        maskedByte = (byte) (address[i] & address[i + maskLength]);
                        otherMaskedByte = (byte) (otherAddress[i] & otherAddress[i + maskLength]);
                        if (maskedByte != otherMaskedByte) {
                            return false;
                        }
                    }
                    // Compare masks
                    for (int i = 0; i < maskLength; i++) {
                        if (address[i + maskLength] != otherAddress[i + maskLength]) {
                            return false;
                        }
                    }
                    return true;
                } else {
                    return MessageDigest.isEqual(address, other.getName());
                }
            }
            return false;
        }

        public int hashCode() {
            return Arrays.hashCode(address);
        }

        private static byte[] parseIPAddress(String strAddress) throws ASN1Exception {
            byte[] addr;
            try {
                if (strAddress.indexOf('.') >= 0) {
                    addr = parseIPv4Address(strAddress);
                } else if (strAddress.indexOf(':') >= 0) {
                    addr = parseIPv6Address(strAddress);
                } else {
                    throw log.asnInvalidGeneralNameForIpAddressType();
                }
            } catch (UnknownHostException e) {
                throw log.asnIpAddressGeneralNameCannotBeResolved(e);
            }
            return addr;
        }

        private static byte[] parseIPv4Address(String strAddress) throws UnknownHostException {
            byte[] addr;
            int slashIndex = strAddress.indexOf('/');
            if (slashIndex == -1) {
                addr = InetAddress.getByName(strAddress).getAddress();
            } else {
                addr = new byte[8];
                byte[] baseAddress = InetAddress.getByName(strAddress.substring(0, slashIndex)).getAddress();
                byte[] mask = InetAddress.getByName(strAddress.substring(slashIndex + 1)).getAddress();
                System.arraycopy(baseAddress, 0, addr, 0, 4);
                System.arraycopy(mask, 0, addr, 4, 4);
            }
            return addr;
        }

        private static byte[] parseIPv6Address(String strAddress) throws ASN1Exception, UnknownHostException {
            byte[] addr;
            int slashIndex = strAddress.indexOf('/');
            if (slashIndex == -1) {
                addr = InetAddress.getByName(strAddress).getAddress();
            } else {
                addr = new byte[32];
                byte[] baseAddress = InetAddress.getByName(strAddress.substring(0, slashIndex)).getAddress();
                System.arraycopy(baseAddress, 0, addr, 0, 16);

                int prefixLength = Integer.parseInt(strAddress.substring(slashIndex + 1));
                if (prefixLength > 128) {
                    throw log.asnInvalidGeneralNameForIpAddressType();
                }
                byte[] mask = new byte[16];
                int maskIndex, bit;
                for (int i = 0; i < prefixLength; i++) {
                    maskIndex = i / 8;
                    bit = 1 << (7 - (i % 8));
                    mask[maskIndex] |= bit;
                }
                System.arraycopy(mask, 0, addr, 16, 16);
            }
            return addr;
        }
    }

    /**
     * A registered ID name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class RegisteredID extends GeneralName {

        private final String name;

        /**
         * Create a registered ID name.
         *
         * @param name the registered ID name, as a {@code String}
         */
        public RegisteredID(final String name) {
            super(REGISTERED_ID);
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.encodeObjectIdentifier(getName());
        }

        public boolean equals(final Object obj) {
            return obj instanceof RegisteredID && equals((RegisteredID) obj);
        }

        public boolean equals(final RegisteredID other) {
            return name.equals(other.getName());
        }

        public int hashCode() {
            return name.hashCode();
        }
    }
}

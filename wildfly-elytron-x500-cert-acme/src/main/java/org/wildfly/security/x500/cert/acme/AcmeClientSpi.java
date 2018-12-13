/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.x500.cert.acme;

import static org.wildfly.security.x500.cert.acme.Acme.ACCEPT_LANGUAGE;
import static org.wildfly.security.x500.cert.acme.Acme.ACCOUNT;
import static org.wildfly.security.x500.cert.acme.Acme.ALG;
import static org.wildfly.security.x500.cert.acme.Acme.AUTHORIZATIONS;
import static org.wildfly.security.x500.cert.acme.Acme.BAD_NONCE;
import static org.wildfly.security.x500.cert.acme.Acme.BASE64_URL;
import static org.wildfly.security.x500.cert.acme.Acme.CAA_IDENTITIES;
import static org.wildfly.security.x500.cert.acme.Acme.CERTIFICATE;
import static org.wildfly.security.x500.cert.acme.Acme.CHALLENGES;
import static org.wildfly.security.x500.cert.acme.Acme.CONTACT;
import static org.wildfly.security.x500.cert.acme.Acme.CONTENT_TYPE;
import static org.wildfly.security.x500.cert.acme.Acme.CSR;
import static org.wildfly.security.x500.cert.acme.Acme.DEACTIVATED;
import static org.wildfly.security.x500.cert.acme.Acme.DETAIL;
import static org.wildfly.security.x500.cert.acme.Acme.DNS;
import static org.wildfly.security.x500.cert.acme.Acme.EXTERNAL_ACCOUNT_REQUIRED;
import static org.wildfly.security.x500.cert.acme.Acme.FINALIZE;
import static org.wildfly.security.x500.cert.acme.Acme.GET;
import static org.wildfly.security.x500.cert.acme.Acme.HEAD;
import static org.wildfly.security.x500.cert.acme.Acme.IDENTIFIER;
import static org.wildfly.security.x500.cert.acme.Acme.IDENTIFIERS;
import static org.wildfly.security.x500.cert.acme.Acme.INSTANCE;
import static org.wildfly.security.x500.cert.acme.Acme.INVALID;
import static org.wildfly.security.x500.cert.acme.Acme.JOSE_JSON_CONTENT_TYPE;
import static org.wildfly.security.x500.cert.acme.Acme.JSON_CONTENT_TYPE;
import static org.wildfly.security.x500.cert.acme.Acme.JWK;
import static org.wildfly.security.x500.cert.acme.Acme.KID;
import static org.wildfly.security.x500.cert.acme.Acme.LOCATION;
import static org.wildfly.security.x500.cert.acme.Acme.META;
import static org.wildfly.security.x500.cert.acme.Acme.NONCE;
import static org.wildfly.security.x500.cert.acme.Acme.OLD_KEY;
import static org.wildfly.security.x500.cert.acme.Acme.ONLY_RETURN_EXISTING;
import static org.wildfly.security.x500.cert.acme.Acme.PAYLOAD;
import static org.wildfly.security.x500.cert.acme.Acme.PEM_CERTIFICATE_CHAIN_CONTENT_TYPE;
import static org.wildfly.security.x500.cert.acme.Acme.PENDING;
import static org.wildfly.security.x500.cert.acme.Acme.POST;
import static org.wildfly.security.x500.cert.acme.Acme.PROBLEM_JSON_CONTENT_TYPE;
import static org.wildfly.security.x500.cert.acme.Acme.PROTECTED;
import static org.wildfly.security.x500.cert.acme.Acme.RATE_LIMITED;
import static org.wildfly.security.x500.cert.acme.Acme.REASON;
import static org.wildfly.security.x500.cert.acme.Acme.REPLAY_NONCE;
import static org.wildfly.security.x500.cert.acme.Acme.RETRY_AFTER;
import static org.wildfly.security.x500.cert.acme.Acme.STATUS;
import static org.wildfly.security.x500.cert.acme.Acme.SUBPROBLEMS;
import static org.wildfly.security.x500.cert.acme.Acme.TERMS_OF_SERVICE;
import static org.wildfly.security.x500.cert.acme.Acme.TOKEN;
import static org.wildfly.security.x500.cert.acme.Acme.URL;
import static org.wildfly.security.x500.cert.acme.Acme.SIGNATURE;
import static org.wildfly.security.x500.cert.acme.Acme.TERMS_OF_SERVICE_AGREED;
import static org.wildfly.security.x500.cert.acme.Acme.TITLE;
import static org.wildfly.security.x500.cert.acme.Acme.TYPE;
import static org.wildfly.security.x500.cert.acme.Acme.USER_ACTION_REQUIRED;
import static org.wildfly.security.x500.cert.acme.Acme.USER_AGENT;
import static org.wildfly.security.x500.cert.acme.Acme.VALID;
import static org.wildfly.security.x500.cert.acme.Acme.VALUE;
import static org.wildfly.security.x500.cert.acme.Acme.WEBSITE;
import static org.wildfly.security.x500.cert.acme.Acme.base64UrlEncode;
import static org.wildfly.security.x500.cert.acme.Acme.getAlgHeaderFromSignatureAlgorithm;
import static org.wildfly.security.x500.cert.acme.Acme.getJwk;
import static org.wildfly.security.x500.cert.acme.ElytronMessages.acme;
import static org.wildfly.security.x500.cert.util.KeyUtil.getDefaultCompatibleSignatureAlgorithmName;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.IDN;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLReason;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.Version;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.X500AttributeTypeAndValue;
import org.wildfly.security.x500.X500PrincipalBuilder;
import org.wildfly.security.x500.cert.PKCS10CertificateSigningRequest;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.SubjectAlternativeNamesExtension;
import org.wildfly.security.x500.cert.X509CertificateChainAndSigningKey;

/**
 * SPI for an <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic Certificate Management Environment (ACME)</a>
 * client provider to implement.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public abstract class AcmeClientSpi {

    /**
     * The default key size that will be used if the key algorithm name is EC.
     */
    public static final int DEFAULT_EC_KEY_SIZE = 256;

    /**
     * The default key size that will be used if the key algorithm name is not EC.
     */
    public static final int DEFAULT_KEY_SIZE = 2048;

    /**
     * The default key algorithm name.
     */
    public static final String DEFAULT_KEY_ALGORITHM_NAME = "RSA";

    private static final int MAX_RETRIES = 10;
    private static final long DEFAULT_RETRY_AFTER_MILLI = 3000;
    private static final int[] CONTENT_TYPE_DELIMS = new int[] {';', '='};
    private static final String CHARSET = "charset";
    private static final String UTF_8 = "utf-8";
    private static final String USER_AGENT_STRING = "Elytron ACME Client/" + Version.getVersion();

    private static final JsonObject EMPTY_PAYLOAD = Json.createObjectBuilder().build();

    /**
     * Get the resource URLs needed to perform operations from the ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return a map of ACME resources to URLs
     * @throws AcmeException if an error occurs while attempting to get the resource URLs from the ACME server
     */
    public Map<AcmeResource, URL> getResourceUrls(AcmeAccount account, boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        final Map<AcmeResource, URL> resourceUrls = account.getResourceUrls(staging);
        if (resourceUrls.isEmpty()) {
            HttpURLConnection connection = sendGetRequest(account.getServerUrl(staging), HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE);
            JsonObject directoryJson = getJsonResponse(connection);
            try {
                for (AcmeResource resource : AcmeResource.values()) {
                    String resourceUrl = getOptionalJsonString(directoryJson, resource.getValue());
                    URL url = resourceUrl != null ? new URL(resourceUrl) : null;
                    resourceUrls.put(resource, url);
                }
            } catch (MalformedURLException e) {
                throw acme.unableToRetrieveAcmeServerDirectoryUrls(e);
            }
        }
        return resourceUrls;
    }

    /**
     * Get the metadata associated with the ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return the metadata associated with the ACME server (may be {@code null})
     * @throws AcmeException if an error occurs while attempting to get the metadata associated with the ACME server
     */
    public AcmeMetadata getMetadata(AcmeAccount account, boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        HttpURLConnection connection = sendGetRequest(account.getServerUrl(staging), HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE);
        JsonObject directoryJson = getJsonResponse(connection);
        JsonObject metadata = directoryJson.getJsonObject(META);
        if (metadata == null) {
            return null;
        }
        AcmeMetadata.Builder metadataBuilder = AcmeMetadata.builder();
        String termsOfServiceUrl = getOptionalJsonString(metadata, TERMS_OF_SERVICE);
        if (termsOfServiceUrl != null) {
            metadataBuilder.setTermsOfServiceUrl(termsOfServiceUrl);
        }
        String websiteUrl = getOptionalJsonString(metadata, WEBSITE);
        if (websiteUrl != null) {
            metadataBuilder.setWebsiteUrl(websiteUrl);
        }
        JsonArray caaIdentitiesArray = metadata.getJsonArray(CAA_IDENTITIES);
        if (caaIdentitiesArray != null) {
            final List<String> caaIdentities = new ArrayList<>(caaIdentitiesArray.size());
            for (JsonString caaIdentity : caaIdentitiesArray.getValuesAs(JsonString.class)) {
                caaIdentities.add(caaIdentity.getString());
            }
            metadataBuilder.setCaaIdentities(caaIdentities.toArray(new String[caaIdentities.size()]));
        }
        boolean externalAccountRequired = metadata.getBoolean(EXTERNAL_ACCOUNT_REQUIRED, false);
        metadataBuilder.setExternalAccountRequired(externalAccountRequired);
        return metadataBuilder.build();
    }

    /**
     * Create an account with an ACME server using the given account information.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return {@code true} if the account was created, {@code false} if the account already existed
     * @throws AcmeException if an error occurs while attempting to create or lookup an account with
     * the ACME server
     */
    public boolean createAccount(AcmeAccount account, boolean staging) throws AcmeException {
        return createAccount(account, staging, false);
    }

    /**
     * Create an account with an ACME server using the given account information.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param onlyReturnExisting {@code true} if the ACME server should not create a new account if one does not
     *                           already exist (this allows an existing account's URL to be looked up and populated
     *                           using the account key)
     * @return {@code true} if the account was created, {@code false} if the account already existed
     * @throws AcmeException if an error occurs while attempting to create or lookup an account with the ACME server
     * or if {@code onlyReturnExisting} is set to {@code true} and the account does not exist
     */
    public boolean createAccount(AcmeAccount account, boolean staging, boolean onlyReturnExisting) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        final String newAccountUrl = getResourceUrl(account, AcmeResource.NEW_ACCOUNT, staging).toString();

        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        if (onlyReturnExisting) {
            payloadBuilder.add(ONLY_RETURN_EXISTING, true);
        } else {
            // create a new account
            payloadBuilder.add(TERMS_OF_SERVICE_AGREED, account.isTermsOfServiceAgreed());
            if (account.getContactUrls() != null && !(account.getContactUrls().length == 0)) {
                JsonArrayBuilder contactBuilder = Json.createArrayBuilder();
                for (String contactUrl : account.getContactUrls()) {
                    contactBuilder.add(contactUrl);
                }
                payloadBuilder.add(CONTACT, contactBuilder.build());
            }
        }

        HttpURLConnection connection = sendPostRequestWithRetries(account, staging, newAccountUrl, true,
                getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_OK);
        account.setAccountUrl(getLocation(connection));
        try {
            return connection.getResponseCode() == HttpURLConnection.HTTP_CREATED;
        } catch (IOException e) {
            throw new AcmeException(e);
        }
    }

    /**
     * Update whether or not the terms of service have been agreed to for an account with an ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param termsOfServiceAgreed the new value for whether or not the terms of service have been agreed to
     * @throws AcmeException if an error occurs while attempting to update the account
     */
    public void updateAccount(AcmeAccount account, boolean staging, boolean termsOfServiceAgreed) throws AcmeException {
        updateAccount(account, staging, termsOfServiceAgreed, null);
    }

    /**
     * Update the contact URLs for an account with an ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param contactUrls the new account contact URLs
     * @throws AcmeException if an error occurs while attempting to update the account
     */
    public void updateAccount(AcmeAccount account, boolean staging, String[] contactUrls) throws AcmeException {
        updateAccount(account, staging, account.isTermsOfServiceAgreed(), contactUrls);
    }

    /**
     * Update an account with an ACME server using the given account information.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param termsOfServiceAgreed the new value for whether or not the terms of service have been agreed to
     * @param contactUrls the new account contact URLs
     * @throws AcmeException if an error occurs while attempting to update the account
     */
    public void updateAccount(AcmeAccount account, boolean staging, boolean termsOfServiceAgreed, String[] contactUrls) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                .add(TERMS_OF_SERVICE_AGREED, termsOfServiceAgreed);
        if (contactUrls != null && ! (contactUrls.length == 0)) {
            JsonArrayBuilder contactBuilder = Json.createArrayBuilder();
            for (String contactUrl : contactUrls) {
                contactBuilder.add(contactUrl);
            }
            payloadBuilder.add(CONTACT, contactBuilder.build());
        }

        sendPostRequestWithRetries(account, staging, getAccountUrl(account, staging), false,
                getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_OK);
        account.setTermsOfServiceAgreed(termsOfServiceAgreed);
        if (contactUrls != null && ! (contactUrls.length == 0)) {
            account.setContactUrls(contactUrls);
        }
    }

    /**
     * Change the key that is associated with the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @throws AcmeException if an error occurs while attempting to change the key that is associated with the given ACME account
     */
    public void changeAccountKey(AcmeAccount account, boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        SelfSignedX509CertificateAndSigningKey newCertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setKeySize(account.getKeySize())
                .setKeyAlgorithmName(account.getKeyAlgorithmName())
                .setDn(account.getDn())
                .build();
        changeAccountKey(account, staging, newCertificateAndSigningKey.getSelfSignedCertificate(), newCertificateAndSigningKey.getSigningKey());
    }

    /**
     * Change the key that is associated with the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param certificate the new certificate to associate with the given ACME account (must not be {@code null})
     * @param privateKey the new private key to associate with the given ACME account (must not be {@code null})
     * @throws AcmeException if an error occurs while attempting to change the key that is associated with the given ACME account
     */
    public void changeAccountKey(AcmeAccount account, boolean staging, X509Certificate certificate, PrivateKey privateKey) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("certificate", certificate);
        Assert.checkNotNullParam("privateKey", privateKey);
        final String keyChangeUrl = getResourceUrl(account, AcmeResource.KEY_CHANGE, staging).toString();
        final String signatureAlgorithm = getDefaultCompatibleSignatureAlgorithmName(privateKey);
        final String algHeader = getAlgHeaderFromSignatureAlgorithm(signatureAlgorithm);
        final String innerEncodedProtectedHeader = getEncodedProtectedHeader(algHeader, certificate.getPublicKey(), keyChangeUrl);
        JsonObjectBuilder innerPayloadBuilder = Json.createObjectBuilder()
                .add(ACCOUNT, getAccountUrl(account, staging))
                .add(OLD_KEY, getJwk(account.getPublicKey(), account.getAlgHeader()));
        final String innerEncodedPayload = getEncodedJson(innerPayloadBuilder.build());
        final String innerEncodedSignature = getEncodedSignature(privateKey, signatureAlgorithm, innerEncodedProtectedHeader, innerEncodedPayload);
        final String outerEncodedPayload = getEncodedJson(getJws(innerEncodedProtectedHeader, innerEncodedPayload, innerEncodedSignature));

        sendPostRequestWithRetries(account, staging, keyChangeUrl, false, outerEncodedPayload, HttpURLConnection.HTTP_OK);
        account.changeCertificateAndPrivateKey(certificate, privateKey); // update account info
    }

    /**
     * Deactivate the given ACME account. It is not possible to reactivate an ACME account after it has
     * been deactivated.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @throws AcmeException if an error occurs while attempting to deactivate the given ACME account
     */
    public void deactivateAccount(AcmeAccount account, boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        JsonObject payload = Json.createObjectBuilder()
                .add(STATUS, DEACTIVATED)
                .build();
        sendPostRequestWithRetries(account, staging, getAccountUrl(account, staging), false, getEncodedJson(payload), HttpURLConnection.HTTP_OK);
    }

    /**
     * Obtain a certificate chain using the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param domainNames the domain names to request the certificate for (must not be {@code null})
     * @return the X509 certificate chain and private key
     * @throws AcmeException if an occur occurs while attempting to obtain the certificate
     */
    public X509CertificateChainAndSigningKey obtainCertificateChain(AcmeAccount account, boolean staging, String... domainNames) throws AcmeException {
        return obtainCertificateChain(account, staging, null, -1, domainNames);
    }

    /**
     * Obtain a certificate chain using the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param keyAlgorithmName the optional key algorithm name to use when generating the key pair (may be {@code null})
     * @param keySize the optional key size to use when generating the key pair (-1 to indicate that the default key size should be used)
     * @param domainNames the domain names to request the certificate for (must not be {@code null})
     * @return the X509 certificate chain and private key
     * @throws AcmeException if an occur occurs while attempting to obtain the certificate
     */
    public X509CertificateChainAndSigningKey obtainCertificateChain(AcmeAccount account, boolean staging, String keyAlgorithmName, int keySize,
                                                                    String... domainNames) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("domainNames", domainNames);
        final LinkedHashSet<String> domainNamesSet = getDomainNames(domainNames);

        // create a new order
        final String newOrderUrl = getResourceUrl(account, AcmeResource.NEW_ORDER, staging).toString();
        JsonArrayBuilder identifiersBuilder = Json.createArrayBuilder();
        for (String domainName : domainNamesSet) {
            JsonObject identifier = Json.createObjectBuilder()
                    .add(TYPE, DNS)
                    .add(VALUE, domainName)
                    .build();
            identifiersBuilder.add(identifier);
        }
        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                .add(IDENTIFIERS, identifiersBuilder.build());
        HttpURLConnection connection = sendPostRequestWithRetries(account, staging, newOrderUrl, false, getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_CREATED);
        JsonObject jsonResponse = getJsonResponse(connection);
        final String finalizeOrderUrl = jsonResponse.getString(FINALIZE);
        final JsonArray authorizationsArray = jsonResponse.getJsonArray(AUTHORIZATIONS);
        final List<String> authorizationUrls = new ArrayList<>(authorizationsArray.size());
        for (JsonString authorization : authorizationsArray.getValuesAs(JsonString.class)) {
            authorizationUrls.add(authorization.getString());
        }

        // respond to challenges for each authorization resource
        List<AcmeChallenge> selectedChallenges = new ArrayList<>(authorizationUrls.size());
        try {
            for (String authorizationUrl : authorizationUrls) {
                connection = sendGetRequest(authorizationUrl, HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE);
                jsonResponse = getJsonResponse(connection);
                AcmeChallenge selectedChallenge = respondToChallenges(account, staging, jsonResponse);
                if (selectedChallenge != null) {
                    selectedChallenges.add(selectedChallenge);
                }
            }

            // poll the authorization resources until server has finished validating the challenge responses
            for (String authorizationUrl : authorizationUrls) {
                jsonResponse = pollResourceUntilFinalized(authorizationUrl);
                if (! jsonResponse.getString(STATUS).equals(VALID)) {
                    throw acme.challengeResponseFailedValidationByAcmeServer();
                }
            }

            // create and submit a CSR now that we've fulfilled the server's requirements
            List<GeneralName> generalNames = new ArrayList<>(domainNamesSet.size());
            for (String domainName : domainNamesSet) {
                generalNames.add(new GeneralName.DNSName(domainName));
            }
            X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
            principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String(((GeneralName.DNSName) generalNames.get(0)).getName())));
            X500Principal dn = principalBuilder.build();
            if (keyAlgorithmName == null) {
                keyAlgorithmName = DEFAULT_KEY_ALGORITHM_NAME;
            }
            if (keySize == -1) {
                if (keyAlgorithmName.equals("EC")) {
                    keySize = DEFAULT_EC_KEY_SIZE;
                } else {
                    keySize = DEFAULT_KEY_SIZE;
                }
            }

            SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                    .setDn(dn)
                    .setKeyAlgorithmName(keyAlgorithmName)
                    .setKeySize(keySize)
                    .build();
            PKCS10CertificateSigningRequest.Builder csrBuilder = PKCS10CertificateSigningRequest.builder()
                    .setCertificate(selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate())
                    .setSigningKey(selfSignedX509CertificateAndSigningKey.getSigningKey())
                    .setSubjectDn(dn);
            csrBuilder.addExtension(new SubjectAlternativeNamesExtension(false, generalNames));

            payloadBuilder = Json.createObjectBuilder()
                    .add(CSR, base64UrlEncode(csrBuilder.build().getEncoded()));
            connection = sendPostRequestWithRetries(account, staging, finalizeOrderUrl, false, getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_OK);
            final String orderUrl = getLocation(connection);

            // poll the order resource until the server has made the certificate chain available
            jsonResponse = pollResourceUntilFinalized(orderUrl);
            if (! jsonResponse.getString(STATUS).equals(VALID)) {
                throw acme.noCertificateWillBeIssuedByAcmeServer();
            }

            // download the certificate chain
            String certificateUrl = getOptionalJsonString(jsonResponse, CERTIFICATE);
            if (certificateUrl == null) {
                throw acme.noCertificateUrlProvidedByAcmeServer();
            }
            connection = sendGetRequest(certificateUrl, HttpURLConnection.HTTP_OK, PEM_CERTIFICATE_CHAIN_CONTENT_TYPE);
            X509Certificate[] certificateChain = getPemCertificateChain(connection);
            PrivateKey privateKey = selfSignedX509CertificateAndSigningKey.getSigningKey();
            return new X509CertificateChainAndSigningKey(certificateChain, privateKey);
        } finally {
            // clean up
            for (AcmeChallenge challenge : selectedChallenges) {
                cleanupAfterChallenge(account, challenge);
            }
        }
    }

    /**
     * Create an authorization for the given identifier.
     * <p>
     * This method allows an ACME client to obtain authorization for an identifier proactively before attempting
     * to obtain a certificate.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param domainName the domain name to create an authorization for (must not be {@code null})
     * @return the authorization URL corresponding to the given identifier
     * @throws AcmeException if an error occurs while attempting to create an authorization for the given identifier
     */
    public String createAuthorization(AcmeAccount account, boolean staging, String domainName) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("domainName", domainName);
        final String newAuthzUrl = getResourceUrl(account, AcmeResource.NEW_AUTHZ, staging).toString();
        JsonObject identifier = Json.createObjectBuilder()
                .add(TYPE, DNS)
                .add(VALUE, getSanitizedDomainName(domainName))
                .build();
        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                .add(IDENTIFIER, identifier);

        HttpURLConnection connection = sendPostRequestWithRetries(account, staging, newAuthzUrl, false,
                getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_CREATED);
        String authorizationUrl = getLocation(connection);
        JsonObject jsonResponse = getJsonResponse(connection);
        AcmeChallenge selectedChallenge = respondToChallenges(account, staging, jsonResponse);
        try {
            jsonResponse = pollResourceUntilFinalized(authorizationUrl);
            if (! jsonResponse.getString(STATUS).equals(VALID)) {
                throw acme.challengeResponseFailedValidationByAcmeServer();
            }
            return authorizationUrl;
        } finally {
            if (selectedChallenge != null) {
                cleanupAfterChallenge(account, selectedChallenge);
            }
        }
    }

    /**
     * Deactivate an authorization.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param authorizationUrl the authorization url (must not be {@code null})
     * @throws AcmeException if an error occurs while attempting to deactivate an authorization for the given identifier
     */
    public void deactivateAuthorization(AcmeAccount account, boolean staging, String authorizationUrl) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("authorizationUrl", authorizationUrl);
        JsonObject payload = Json.createObjectBuilder()
                .add(STATUS, DEACTIVATED)
                .build();
        sendPostRequestWithRetries(account, staging, authorizationUrl, false, getEncodedJson(payload), HttpURLConnection.HTTP_OK);
    }

    /**
     * Prove control of the identifier associated with the given list of challenges.
     * <p>
     * This method should select one challenge from the given list of challenges from the ACME server to prove
     * control of the identifier associated with the challenges as specified by the ACME v2 protocol.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param challenges the list of challenges from the ACME server (must not be {@code null})
     * @return the challenge that was selected and used to prove control of the identifier
     * @throws AcmeException if an error occurs while attempting to provide control of the identifier associated
     * with the challenges or if none of the challenge types are supported by this client
     */
    public abstract AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException;

    /**
     * Undo the actions that were taken to prove control of the identifier associated with the given challenge.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param challenge the challenge (must not be {@code null})
     * @throws AcmeException if an error occurs while attempting to undo the actions that were taken to prove control
     * of the identifier associated with the given challenge
     */
    public abstract void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException;

    /**
     * Revoke the given certificate.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param certificate the certificate to be revoked (must not be {@code null})
     * @throws AcmeException if an error occurs while attempting to revoke the given certificate
     */
    public void revokeCertificate(AcmeAccount account, boolean staging, X509Certificate certificate) throws AcmeException {
        revokeCertificate(account, staging, certificate, null);
    }

    /**
     * Revoke the given certificate.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param certificate the certificate to be revoked (must not be {@code null})
     * @param reason the optional reason why the certificate is being revoked (may be {@code null})
     * @throws AcmeException if an error occurs while attempting to revoke the given certificate
     */
    public void revokeCertificate(AcmeAccount account, boolean staging, X509Certificate certificate, CRLReason reason) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("certificate", certificate);
        final String revokeCertUrl = getResourceUrl(account, AcmeResource.REVOKE_CERT, staging).toString();

        byte[] encodedCertificate;
        try {
            encodedCertificate = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw acme.unableToGetEncodedFormOfCertificateToBeRevoked(e);
        }
        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                .add(CERTIFICATE, base64UrlEncode(encodedCertificate));
        if (reason != null) {
            payloadBuilder.add(REASON, reason.ordinal());
        }
        sendPostRequestWithRetries(account, staging, revokeCertUrl, false, getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_OK);
    }

    /**
     * Get a new nonce for the given account from the ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return nonce the new nonce for the given account
     * @throws AcmeException if an error occurs while attempting to get the new nonce from the ACME server
     */
    public byte[] getNewNonce(final AcmeAccount account, final boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        try {
            final URL newNonceUrl = getResourceUrl(account, AcmeResource.NEW_NONCE, staging);
            HttpURLConnection connection = (HttpURLConnection) newNonceUrl.openConnection();
            connection.setRequestMethod(HEAD);
            connection.setRequestProperty(ACCEPT_LANGUAGE, Locale.getDefault().toLanguageTag());
            connection.setRequestProperty(USER_AGENT, USER_AGENT_STRING);
            connection.connect();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_NO_CONTENT && responseCode != HttpURLConnection.HTTP_OK) {
                handleAcmeErrorResponse(connection, responseCode);
            }
            byte[] nonce = getReplayNonce(connection);
            if (nonce == null) {
                throw acme.noNonceProvidedByAcmeServer();
            }
            return nonce;
        } catch (Exception e) {
            throw acme.unableToObtainNewNonceFromAcmeServer();
        }
    }

    String[] queryAccountContactUrls(AcmeAccount account, boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        HttpURLConnection connection = sendPostRequestWithRetries(account, staging, getAccountUrl(account, staging), false,
                getEncodedJson(EMPTY_PAYLOAD), HttpURLConnection.HTTP_OK);
        JsonObject jsonResponse = getJsonResponse(connection);
        JsonArray contactsArray = jsonResponse.getJsonArray(CONTACT);
        if (contactsArray != null && contactsArray.size() > 0) {
            List<String> contacts = new ArrayList<>(contactsArray.size());
            for (JsonString contact : contactsArray.getValuesAs(JsonString.class)) {
                contacts.add(contact.getString());
            }
            return contacts.toArray(new String[contacts.size()]);
        }
        return null;
    }

    String queryAccountStatus(AcmeAccount account, boolean staging) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        HttpURLConnection connection = sendPostRequestWithRetries(account, staging, getAccountUrl(account, staging), false,
                getEncodedJson(EMPTY_PAYLOAD), HttpURLConnection.HTTP_OK);
        JsonObject jsonResponse = getJsonResponse(connection);
        return jsonResponse.getString(STATUS);
    }

    private URL getResourceUrl(AcmeAccount account, AcmeResource resource, boolean staging) throws AcmeException {
        URL resourceUrl = getResourceUrls(account, staging).get(resource);
        if (resourceUrl == null) {
            throw acme.resourceNotSupportedByAcmeServer(resource.getValue());
        }
        return resourceUrl;
    }

    private HttpURLConnection sendGetRequest(String resourceUrl, int expectedResponseCode, String expectedContentType) throws AcmeException {
        try {
            final URL directoryUrl = new URL(resourceUrl);
            HttpURLConnection connection = (HttpURLConnection) directoryUrl.openConnection();
            connection.setRequestMethod(GET);
            connection.setRequestProperty(ACCEPT_LANGUAGE, Locale.getDefault().toLanguageTag());
            connection.setRequestProperty(USER_AGENT, USER_AGENT_STRING);
            connection.connect();
            int responseCode = connection.getResponseCode();
            if (responseCode != expectedResponseCode) {
                handleAcmeErrorResponse(connection, responseCode);
            }
            String contentType = connection.getContentType();
            if (! checkContentType(connection, expectedContentType)) {
                throw acme.unexpectedContentTypeFromAcmeServer(contentType);
            }
            return connection;
        } catch (Exception e) {
            if (e instanceof AcmeException) {
                throw (AcmeException) e;
            } else {
                throw new AcmeException(e);
            }
        }
    }

    private HttpURLConnection sendPostRequestWithRetries(AcmeAccount account, boolean staging, String resourceUrl, boolean useJwk, String encodedPayload,
                                                         int... expectedResponseCodes) throws AcmeException {
        try {
            final URL url = new URL(resourceUrl);
            HttpURLConnection connection;
            for (int i = 0; i < MAX_RETRIES; i++) {
                String encodedProtectedHeader = getEncodedProtectedHeader(useJwk, resourceUrl, account, staging);
                String encodedSignature = getEncodedSignature(account.getPrivateKey(), account.getSignature(), encodedProtectedHeader, encodedPayload);
                JsonObject jws = getJws(encodedProtectedHeader, encodedPayload, encodedSignature);
                connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod(POST);
                connection.setRequestProperty(CONTENT_TYPE, JOSE_JSON_CONTENT_TYPE);
                connection.setRequestProperty(ACCEPT_LANGUAGE, Locale.getDefault().toLanguageTag());
                connection.setRequestProperty(USER_AGENT, USER_AGENT_STRING);
                connection.setDoOutput(true);
                connection.setFixedLengthStreamingMode(jws.toString().length());
                connection.connect();
                try (OutputStream out = connection.getOutputStream()) {
                    out.write(jws.toString().getBytes(StandardCharsets.US_ASCII));
                }
                int responseCode = connection.getResponseCode();

                account.setNonce(getReplayNonce(connection)); // update the account nonce

                for (int expectedResponseCode : expectedResponseCodes) {
                    if (expectedResponseCode == responseCode) {
                        return connection;
                    }
                }
                handleAcmeErrorResponse(connection, responseCode);
            }
            throw acme.badAcmeNonce(); // max attempts reached
        } catch (Exception e) {
            if (e instanceof AcmeException) {
                throw (AcmeException) e;
            } else {
                throw new AcmeException(e);
            }
        }
    }

    private JsonObject pollResourceUntilFinalized(String resourceUrl) throws AcmeException {
        boolean statusFinalized;
        JsonObject jsonResponse;
        do {
            statusFinalized = true;
            HttpURLConnection connection = sendGetRequest(resourceUrl, HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE);
            jsonResponse = getJsonResponse(connection);
            String status = jsonResponse.getString(STATUS);
            if (! status.equals(VALID) && ! status.equals(INVALID)) {
                // server still processing the client response, try again after some time
                statusFinalized = false;
                long retryAfterMilli = getRetryAfter(connection, true);
                if (retryAfterMilli > 0) {
                    try {
                        Thread.sleep(retryAfterMilli);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException(e);
                    }
                }
            }
        } while (! statusFinalized);
        return jsonResponse;
    }

    private AcmeChallenge respondToChallenges(AcmeAccount account, boolean staging, JsonObject authorization) throws AcmeException {
        List<AcmeChallenge> challenges = null;
        if (authorization.getString(STATUS).equals(PENDING)) {
            JsonObject identifier = authorization.getJsonObject(IDENTIFIER);
            JsonArray challengeArray = authorization.getJsonArray(CHALLENGES);
            challenges = new ArrayList<>(challengeArray.size());
            for (JsonObject challenge : challengeArray.getValuesAs(JsonObject.class)) {
                challenges.add(new AcmeChallenge(AcmeChallenge.Type.forName(challenge.getString(TYPE)), challenge.getString(URL),
                        challenge.getString(TOKEN), identifier.getString(TYPE), identifier.getString(VALUE)));
            }
        }
        if (challenges != null && ! challenges.isEmpty()) {
            AcmeChallenge selectedChallenge = proveIdentifierControl(account, challenges);
            try {
                sendPostRequestWithRetries(account, staging, selectedChallenge.getUrl(), false, getEncodedJson(EMPTY_PAYLOAD), HttpURLConnection.HTTP_OK);
                return selectedChallenge;
            } catch (AcmeException e) {
                cleanupAfterChallenge(account, selectedChallenge);
                throw e;
            }
        }
        return null;
    }

    private static LinkedHashSet<String> getDomainNames(String[] domainNames) throws AcmeException {
        if (domainNames.length == 0) {
            throw acme.domainNamesIsEmpty();
        }
        final LinkedHashSet<String> domainNamesSet = new LinkedHashSet<>();
        for (String domainName : domainNames) {
            domainNamesSet.add(getSanitizedDomainName(domainName));
        }
        return domainNamesSet;
    }

    private static String getSanitizedDomainName(String domainName) throws AcmeException {
        if (domainName == null) {
            throw acme.domainNameIsNull();
        }
        domainName = IDN.toASCII(domainName.trim());
        return domainName.toLowerCase(Locale.ROOT);
    }

    /* -- Methods used to parse responses from the ACME server -- */

    private static JsonObject getJsonResponse(HttpURLConnection connection) throws AcmeException {
        JsonObject jsonResponse;
        try (InputStream inputStream = new BufferedInputStream(connection.getResponseCode() < 400 ? connection.getInputStream() : connection.getErrorStream())) {
            jsonResponse = Json.createReader(inputStream).readObject();
        } catch (IOException e) {
            throw acme.unableToObtainJsonResponseFromAcmeServer(e);
        }
        return jsonResponse;
    }

    private static byte[] getReplayNonce(HttpURLConnection connection) throws AcmeException {
        String nonce = connection.getHeaderField(REPLAY_NONCE);
        if (nonce == null) {
            return null;
        }
        return CodePointIterator.ofString(nonce).base64Decode(BASE64_URL, false).drain();
    }

    private static String getLocation(HttpURLConnection connection) throws AcmeException {
        String location = connection.getHeaderField(LOCATION);
        if (location == null) {
            throw acme.noAccountLocationUrlProvidedByAcmeServer();
        }
        return location;
    }

    private static long getRetryAfter(HttpURLConnection connection, boolean useDefaultIfHeaderNotPresent) throws AcmeException {
        long retryAfterMilli  = -1;
        String retryAfter = connection.getHeaderField(RETRY_AFTER);
        if (retryAfter != null) {
            try {
                retryAfterMilli = Integer.parseInt(retryAfter) * 1000;
            } catch (NumberFormatException e) {
                long retryAfterDate = connection.getHeaderFieldDate(RETRY_AFTER, 0L);
                if (retryAfterDate != 0) {
                    retryAfterMilli = retryAfterDate - Instant.now().toEpochMilli();
                }
            }
        }

        if (retryAfterMilli == -1) {
            if (useDefaultIfHeaderNotPresent) {
                retryAfterMilli = DEFAULT_RETRY_AFTER_MILLI;
            }
        }
        return retryAfterMilli;
    }

    private static void handleAcmeErrorResponse(HttpURLConnection connection, int responseCode) throws AcmeException {
        try {
            String responseMessage = connection.getResponseMessage();
            if (! checkContentType(connection, PROBLEM_JSON_CONTENT_TYPE)) {
                throw acme.unexpectedResponseCodeFromAcmeServer(responseCode, responseMessage);
            }
            JsonObject jsonResponse = getJsonResponse(connection);
            String type = getOptionalJsonString(jsonResponse, TYPE);
            if (type != null) {
                if (type.equals(BAD_NONCE)) {
                    return; // the request will be re-attempted
                } else if (type.equals(USER_ACTION_REQUIRED)) {
                    String instance = getOptionalJsonString(jsonResponse, INSTANCE);
                    if (instance != null) {
                        throw acme.userActionRequired(instance);
                    }
                } else if (type.equals(RATE_LIMITED)) {
                    long retryAfter = getRetryAfter(connection, false);
                    if (retryAfter > 0) {
                        throw acme.rateLimitExceededTryAgainLater(Instant.ofEpochMilli(retryAfter));
                    } else {
                        throw acme.rateLimitExceeded();
                    }
                }
            }
            String problemMessages = getProblemMessages(jsonResponse);
            if (problemMessages != null && ! problemMessages.isEmpty()) {
                throw new AcmeException(problemMessages);
            } else {
                throw acme.unexpectedResponseCodeFromAcmeServer(responseCode, responseMessage);
            }
        } catch (Exception e) {
            if (e instanceof AcmeException) {
                throw (AcmeException) e;
            } else {
                throw new AcmeException(e);
            }
        }
    }

    private static String getProblemMessages(JsonObject errorResponse) {
        StringBuilder problemMessages = new StringBuilder();
        String mainProblem = getProblemMessage(errorResponse);
        if (mainProblem != null) {
            problemMessages.append(getProblemMessage(errorResponse));
        }
        JsonArray subproblems = errorResponse.getJsonArray(SUBPROBLEMS);
        if (subproblems != null && subproblems.size() > 0) {
            problemMessages.append(":");
            for (JsonObject subproblem : subproblems.getValuesAs(JsonObject.class)) {
                problemMessages.append("\n").append(getProblemMessage(subproblem));
            }
        }
        return problemMessages.toString();
    }

    private static String getProblemMessage(JsonObject jsonResponse) {
        String type = getOptionalJsonString(jsonResponse, TYPE);
        String detail = getOptionalJsonString(jsonResponse, DETAIL);
        String title = getOptionalJsonString(jsonResponse, TITLE);
        String problemMessage = null;
        if (detail != null) {
            problemMessage = detail;
        } else if (title != null) {
            problemMessage = title;
        } else if (type != null) {
            problemMessage = type;
        }
        return problemMessage;
    }

    private static String getOptionalJsonString(JsonObject jsonObject, String name) {
        JsonString value = jsonObject.getJsonString(name);
        if (value == null) {
            return null;
        }
        return value.getString();
    }

    private static X509Certificate[] getPemCertificateChain(HttpURLConnection connection) throws AcmeException {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> reply;
            try (InputStream inputStream = new BufferedInputStream(getConvertedInputStream(connection.getInputStream()))) {
                reply = certificateFactory.generateCertificates(inputStream);
            }
            return X500.asX509CertificateArray(reply.toArray(new Certificate[reply.size()]));
        } catch (CertificateException | IOException e) {
            throw acme.unableToDownloadCertificateChainFromAcmeServer(e);
        }
    }

    /* -- Methods used to encode JWS messages to send to the ACME server -- */

    private static String getEncodedJson(JsonObject jsonObject) {
        return CodePointIterator.ofString(jsonObject.toString()).asUtf8().base64Encode(BASE64_URL, false).drainToString();
    }

    private static JsonObject getJws(String encodedProtectedHeader, String encodedPayload, String encodedSignature) {
        return Json.createObjectBuilder()
                .add(PROTECTED, encodedProtectedHeader)
                .add(PAYLOAD, encodedPayload)
                .add(SIGNATURE, encodedSignature)
                .build();
    }

    private static String getEncodedProtectedHeader(String algHeader, PublicKey publicKey, String resourceUrl) {
        JsonObject protectedHeader = Json.createObjectBuilder()
                .add(ALG, algHeader)
                .add(JWK, getJwk(publicKey, algHeader))
                .add(URL, resourceUrl)
                .build();
        return getEncodedJson(protectedHeader);
    }

    private String getEncodedProtectedHeader(boolean useJwk, String resourceUrl, AcmeAccount account, boolean staging) throws AcmeException {
        JsonObjectBuilder protectedHeaderBuilder = Json.createObjectBuilder().add(ALG, account.getAlgHeader());
        if (useJwk) {
            protectedHeaderBuilder.add(JWK, getJwk(account.getPublicKey(), account.getAlgHeader()));
        } else {
            protectedHeaderBuilder.add(KID, getAccountUrl(account, staging));
        }
        protectedHeaderBuilder
                .add(NONCE, base64UrlEncode(getNonce(account, staging)))
                .add(URL, resourceUrl);
        return getEncodedJson(protectedHeaderBuilder.build());
    }

    private static String getEncodedSignature(PrivateKey privateKey, Signature signature, String encodedProtectedHeader, String encodedPayload) throws AcmeException {
        final byte[] signatureBytes;
        try {
            signature.update((encodedProtectedHeader + "." + encodedPayload).getBytes(StandardCharsets.UTF_8));
            signatureBytes = signature.sign();
            if (privateKey instanceof ECPrivateKey) {
                // need to convert the DER encoded signature to concatenated bytes
                DERDecoder derDecoder = new DERDecoder(signatureBytes);
                derDecoder.startSequence();
                byte[] r = derDecoder.drainElementValue();
                byte[] s = derDecoder.drainElementValue();
                derDecoder.endSequence();
                int rLength = r.length;
                int sLength = s.length;
                int rActual = rLength;
                int sActual = sLength;
                while (rActual > 0 && r[rLength - rActual] == 0) {
                    rActual--;
                }
                while (sActual > 0 && s[sLength - sActual] == 0) {
                    sActual--;
                }
                int rawLength = Math.max(rActual, sActual);
                int signatureByteLength = getECSignatureByteLength(signature.getAlgorithm());
                rawLength = Math.max(rawLength, signatureByteLength / 2);
                byte[] concatenatedSignatureBytes = new byte[rawLength * 2];
                System.arraycopy(r, rLength - rActual, concatenatedSignatureBytes, rawLength - rActual, rActual);
                System.arraycopy(s, sLength - sActual, concatenatedSignatureBytes, 2 * rawLength - sActual, sActual);
                return base64UrlEncode(concatenatedSignatureBytes);
            }
            return base64UrlEncode(signatureBytes);
        } catch (SignatureException e) {
            throw acme.unableToCreateAcmeSignature(e);
        }
    }

    private static String getEncodedSignature(PrivateKey privateKey, String signatureAlgorithm, String encodedProtectedHeader, String encodedPayload) throws AcmeException {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            return getEncodedSignature(privateKey, signature, encodedProtectedHeader, encodedPayload);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw acme.unableToCreateAcmeSignature(e);
        }
    }

    private static int getECSignatureByteLength(String signatureAlgorithm) throws AcmeException {
        switch(signatureAlgorithm) {
            case "SHA256withECDSA":
                return 64;
            case "SHA384withECDSA":
                return 96;
            case "SHA512withECDSA":
                return 132;
            default:
                throw acme.unsupportedAcmeAccountSignatureAlgorithm(signatureAlgorithm);
        }
    }

    private byte[] getNonce(AcmeAccount account, boolean staging) throws AcmeException {
        byte[] nonce = account.getNonce();
        if (nonce == null) {
            nonce = getNewNonce(account, staging);
        }
        return nonce;
    }

    private String getAccountUrl(AcmeAccount account, boolean staging) throws AcmeException {
        String accountUrl = account.getAccountUrl();
        if (accountUrl == null) {
            createAccount(account, staging, true);
            accountUrl = account.getAccountUrl();
            if (accountUrl == null) {
                acme.acmeAccountDoesNotExist();
            }
        }
        return accountUrl;
    }

    private static boolean checkContentType(HttpURLConnection connection, String expectedMediaType) throws AcmeException {
        String contentType = connection.getContentType();
        if (contentType == null) {
            return false;
        }
        CodePointIterator cpi = CodePointIterator.ofString(contentType);
        CodePointIterator di = cpi.delimitedBy(CONTENT_TYPE_DELIMS);
        String mediaType = di.drainToString().trim();
        skipDelims(di, cpi, CONTENT_TYPE_DELIMS);
        while (di.hasNext()) {
            String parameter = di.drainToString().trim();
            skipDelims(di, cpi, CONTENT_TYPE_DELIMS);
            if (parameter.equalsIgnoreCase(CHARSET)) {
                String value = di.drainToString().trim();
                if (! value.equalsIgnoreCase(UTF_8)) {
                    return false;
                }
            }
        }
        return mediaType.equalsIgnoreCase(expectedMediaType);
    }

    private static void skipDelims(CodePointIterator di, CodePointIterator cpi, int...delims) throws AcmeException {
        while ((! di.hasNext()) && cpi.hasNext()) {
            if (! isDelim(cpi.next(), delims)) {
                throw acme.invalidContentTypeFromAcmeServer();
            }
        }
    }

    private static boolean isDelim(int c, int... delims) {
        for (int delim : delims) {
            if (delim == c) {
                return true;
            }
        }
        return false;
    }

    private static InputStream getConvertedInputStream(InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String currentLine;
            while ((currentLine = reader.readLine()) != null) {
                // ignore any blank lines to avoid parsing issues on IBM JDK
                if (! currentLine.trim().isEmpty()) {
                    sb.append(currentLine + System.lineSeparator());
                }
            }
        }
        return new ByteArrayInputStream(sb.toString().getBytes(StandardCharsets.UTF_8));
    }
}

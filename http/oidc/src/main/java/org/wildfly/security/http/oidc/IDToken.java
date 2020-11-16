/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.util.Map;

import javax.json.JsonObject;
import javax.json.JsonValue;

import org.jose4j.jwt.JwtClaims;

/**
 * Representation of an OIDC ID token, as per <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IDToken extends JsonWebToken {

    public static final String AT_HASH = "at_hash";
    public static final String C_HASH = "c_hash";
    public static final String NAME = "name";
    public static final String GIVEN_NAME = "given_name";
    public static final String FAMILY_NAME = "family_name";
    public static final String MIDDLE_NAME = "middle_name";
    public static final String NICKNAME = "nickname";
    public static final String PREFERRED_USERNAME = "preferred_username";
    public static final String PROFILE = "profile";
    public static final String PICTURE = "picture";
    public static final String WEBSITE = "website";
    public static final String EMAIL = "email";
    public static final String EMAIL_VERIFIED = "email_verified";
    public static final String GENDER = "gender";
    public static final String BIRTHDATE = "birthdate";
    public static final String ZONEINFO = "zoneinfo";
    public static final String LOCALE = "locale";
    public static final String PHONE_NUMBER = "phone_number";
    public static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    public static final String ADDRESS = "address";
    public static final String UPDATED_AT = "updated_at";
    public static final String CLAIMS_LOCALES = "claims_locales";
    public static final String ACR = "acr";
    public static final String S_HASH = "s_hash";
    public static final String SUB = "sub";

    /**
     * Construct a new instance.
     *
     * @param jwtClaims the JWT claims for this instance (may not be {@code null})
     */
    public IDToken(JwtClaims jwtClaims) {
        super(jwtClaims);
    }

    /**
     * Get the name claim.
     *
     * @return the name claim
     */
    public String getName() {
        return getClaimValueAsString(NAME);
    }

    /**
     * Get the given name claim.
     *
     * @return the given name claim
     */
    public String getGivenName() {
        return getClaimValueAsString(GIVEN_NAME);
    }

    /**
     * Get the family name claim.
     *
     * @return the family name claim
     */
    public String getFamilyName() {
        return getClaimValueAsString(FAMILY_NAME);
    }

    /**
     * Get the middle name claim.
     *
     * @return the middle name claim
     */
    public String getMiddleName() {
        return getClaimValueAsString(MIDDLE_NAME);
    }

    /**
     * Get the nick name claim.
     *
     * @return the nick name claim
     */
    public String getNickName() {
        return getClaimValueAsString(NICKNAME);
    }

    /**
     * Get the preferred username claim.
     *
     * @return the preferred username claim
     */
    public String getPreferredUsername() {
        return getClaimValueAsString(PREFERRED_USERNAME);
    }

    /**
     * Get the profile claim.
     *
     * @return the profile claim
     */
    public String getProfile() {
        return getClaimValueAsString(PROFILE);
    }

    /**
     * Get the picture claim.
     *
     * @return the picture claim
     */
    public String getPicture() {
        return getClaimValueAsString(PICTURE);
    }

    /**
     * Get the website claim.
     *
     * @return the website claim
     */
    public String getWebsite() {
        return getClaimValueAsString(WEBSITE);
    }

    /**
     * Get the email claim.
     *
     * @return the email claim
     */
    public String getEmail() {
        return getClaimValueAsString(EMAIL);
    }

    /**
     * Get the email verified claim.
     *
     * @return the email verified claim
     */
    public Boolean getEmailVerified() {
        return getClaimValue(EMAIL_VERIFIED, Boolean.class);
    }

    /**
     * Get the gender claim.
     *
     * @return the gender claim
     */
    public String getGender() {
        return getClaimValueAsString(GENDER);
    }

    /**
     * Get the birth date claim.
     *
     * @return the birthdate claim
     */
    public String getBirthdate() {
        return getClaimValueAsString(BIRTHDATE);
    }

    /**
     * Get the zone info claim.
     *
     * @return the zone info claim
     */
    public String getZoneinfo() {
        return getClaimValueAsString(ZONEINFO);
    }

    /**
     * Get the locale claim.
     *
     * @return the locale claim
     */
    public String getLocale() {
        return getClaimValueAsString(LOCALE);
    }

    /**
     * Get the phone number claim.
     *
     * @return the phone number claim
     */
    public String getPhoneNumber() {
        return getClaimValueAsString(PHONE_NUMBER);
    }

    /**
     * Get the phone number verified claim.
     *
     * @return the phone number verified claim
     */
    public Boolean getPhoneNumberVerified() {
        return getClaimValue(PHONE_NUMBER_VERIFIED, Boolean.class);
    }

    /**
     * Get the address claim.
     *
     * @return the address claim
     * @throws IllegalArgumentException if the address claim is malformed
     */
    public AddressClaimSet getAddress() {
        Object addressValue = getClaimValue(ADDRESS);
        JsonValue addressValueAsJson = wrapValue(addressValue);
        if (! (addressValueAsJson instanceof JsonObject)) {
            throw log.invalidTokenClaimValue();
        }
        return new AddressClaimSet((Map<String, String>) addressValueAsJson);
    }

    /**
     * Get the updated at claim.
     *
     * @return the updated at claim
     */
    public Long getUpdatedAt() {
        return getClaimValueAsLong(UPDATED_AT);
    }

    /**
     * Get the claims locales.
     *
     * @return the cliams locales
     */
    public String getClaimsLocales() {
        return getClaimValueAsString(CLAIMS_LOCALES);
    }

    /**
     * Get the access token hash claim.
     *
     * @return the access token hash claim
     */
    public String getAccessTokenHash() {
        return getClaimValueAsString(AT_HASH);
    }

    /**
     * Get the code hash claim.
     *
     * @return the code hash claim
     */
    public String getCodeHash() {
        return getClaimValueAsString(C_HASH);
    }

    /**
     * Get the state hash claim.
     *
     * @return the state hash claim
     */
    public String getStateHash() {
        return getClaimValueAsString(S_HASH);
    }

    /**
     * Get the acr claim.
     *
     * @return the acr claim
     */
    public String getAcr() {
        return getClaimValueAsString(ACR);
    }

    public String getPrincipalName(OidcClientConfiguration deployment) {
        String attr = SUB;
        if (deployment.getPrincipalAttribute() != null) {
            attr = deployment.getPrincipalAttribute();
        }
        switch (attr) {
            case SUB:
                return getSubject();
            case EMAIL:
                return getEmail();
            case PREFERRED_USERNAME:
                return getPreferredUsername();
            case NAME:
                return getName();
            case GIVEN_NAME:
                return getGivenName();
            case FAMILY_NAME:
                return getFamilyName();
            case NICKNAME:
                return getNickName();
            default:
                return getSubject();
        }
    }


}

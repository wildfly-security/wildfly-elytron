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

package org.wildfly.security.keystore;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * LDAP timestamp (Generalized time as defined in RFC 4517) util
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class LdapGeneralizedTimeUtil {
    /**
     * Convert Generalized Time as defined in RFC4517 to the Date
     */
    static Date generalizedTimeToDate(String generalized) throws ParseException {

        String[] parts = generalized.split("[Z+-]");
        String[] timeFraction = parts[0].split("[.,]");
        String time = timeFraction[0];

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(0);
        calendar.setLenient(false);

        calendar.set(Calendar.YEAR, Integer.parseInt(time.substring(0, 4)));
        calendar.set(Calendar.MONTH, Integer.parseInt(time.substring(4, 6)) - 1);
        calendar.set(Calendar.DAY_OF_MONTH, Integer.parseInt(time.substring(6, 8)));
        calendar.set(Calendar.HOUR_OF_DAY, Integer.parseInt(time.substring(8, 10)));
        if (time.length() >= 12) calendar.set(Calendar.MINUTE, Integer.parseInt(time.substring(10, 12)));
        if (time.length() >= 14) calendar.set(Calendar.SECOND, Integer.parseInt(time.substring(12, 14)));

        // fraction
        if (timeFraction.length >= 2) {
            double fraction = Double.parseDouble("0." + timeFraction[1]);
            if (time.length() >= 14) { // fraction of second
                calendar.set(Calendar.MILLISECOND, (int) Math.round(fraction * 1000));
            } else if (time.length() >= 12) { // fraction of minute
                calendar.set(Calendar.SECOND, (int) Math.round(fraction * 60));
            } else { // fraction of hour
                calendar.set(Calendar.MINUTE, (int) Math.round(fraction * 60));
            }
        }

        // timezone
        if (generalized.length() > parts[0].length()) {
            char delimiter = generalized.charAt(parts[0].length());
            if (delimiter == 'Z') {
                calendar.setTimeZone(TimeZone.getTimeZone("GMT"));
            } else {
                calendar.setTimeZone(TimeZone.getTimeZone("GMT" + delimiter + parts[1]));
            }
        }

        return calendar.getTime();
    }
}

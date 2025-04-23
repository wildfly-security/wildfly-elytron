package org.wildfly.elytron.site;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import io.quarkiverse.roq.frontmatter.runtime.model.RoqCollection;
import io.quarkus.qute.TemplateExtension;

@TemplateExtension
public class Extensions {

    public static String format(Date date, String format) {
        return new SimpleDateFormat(format).format(date);
    }

    public static String[] tags(RoqCollection collection) {
        Set<String> tags = new HashSet<>();
        collection.forEach(page -> {
            if (page.data().containsKey("tags")) {
                tags.addAll(Arrays.asList(splitTags(page.data().getString("tags"))));
            }
        });

        String[] array = tags.toArray(new String[0]);
        Arrays.sort(array);
        return array;
    }

    public static String[] splitTags(String rawText) {
        return rawText.toLowerCase(Locale.ROOT).split(",");
    }

}

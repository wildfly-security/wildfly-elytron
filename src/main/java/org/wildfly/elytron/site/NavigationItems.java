package org.wildfly.elytron.site;

import java.util.List;

import io.quarkiverse.roq.data.runtime.annotations.DataMapping;
import io.quarkiverse.roq.frontmatter.runtime.model.Page;

@DataMapping(value = "navigationItems", parentArray = true)
public record NavigationItems(List<NavigationItem> list) {
    public record NavigationItem(String name, String link) {
        public String getCssClass(Page page) {
            String cssClass = "mdl-navigation__link";

            var baseUrl = page.site().url().path();
            var pageUrl = page.url().path();
            var link = baseUrl + link().substring(1);
            var name = name();

            if ((pageUrl.equals(link)) ||
                (pageUrl.equals("blog") && name.equals("Blog")) ||
                (pageUrl.equals("OSD") && name.equals("Open Source Day")) ||
                (pageUrl.equals("hacktoberfest") && name.equals("Hacktoberfest"))) {
                cssClass = cssClass + " mdl-navigation__link--current";
            }

            if (name.equals("Open Source Day") ||
                name.equals("Hacktoberfest")) {
                cssClass = cssClass + " highlight-button";
            }

            return cssClass;
        }
    }
}

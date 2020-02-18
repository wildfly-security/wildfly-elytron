# Elytron Project Website Based on Jekyll

## Getting Started

These instructions will allow you to run the Elytron website locally for development and testing purposes.

### Installation
The following steps are based on the [Jekyll static site generator docs](https://jekyllrb.com/docs/).

1. Install a full [Ruby development environment](https://jekyllrb.com/docs/installation/)
2. Install jekyll and [bundler](https://jekyllrb.com/docs/ruby-101/#bundler)  [gems](https://jekyllrb.com/docs/ruby-101/#gems) 
  
        gem install jekyll bundler

3. Fork the [project repository](https://github.com/wildfly-security/wildfly-elytron), then clone your fork.
  
        git clone git@github.com:YOUR_USER_NAME/wildfly-elytron.git

4. Change into the project directory:
  
        cd wildfly-elytron

5. Checkout the [develop](https://github.com/wildfly-security/wildfly-elytron/tree/develop) branch:
  
        git checkout develop

6. Use bundler to fetch all required gems in their respective versions

        bundle install

7. Build the site and make it available on a local server
  
        bundle exec jekyll serve

   If you encounter the following message:

        FATAL: Listen error: unable to monitor directories for changes.  
        
   Please refer to these [instructions](https://github.com/guard/listen/wiki/Increasing-the-amount-of-inotify-watchers) to fix this.       
        
8. Now browse to http://localhost:4000/wildfly-elytron/

> If you encounter any unexpected errors during the above, please refer to the [troubleshooting](https://jekyllrb.com/docs/troubleshooting/#configuration-problems) page or the [requirements](https://jekyllrb.com/docs/installation/#requirements) page, as you might be missing development headers or other prerequisites.


**For more regarding the use of Jekyll, please refer to the [Jekyll Step by Step Tutorial](https://jekyllrb.com/docs/step-by-step/01-setup/).**

## Writing a blog post

To write a blog post:

- Add an author entry in [_data/authors.yaml](https://github.com/wildfly-security/wildfly-elytron/tree/gh-pages/_data/authors.yaml)
    - `emailhash` is used to fetch your picture from the Gravatar service
- Create a blog post entry under [_posts](https://github.com/wildfly-security/wildfly-elytron/tree/gh-pages/_posts)
    - The file name should be `yyyy-mm-dd-slug.adoc`
- Your blog post should be in asciidoc format (take a look at other blogs posts in the _posts directory to see examples)
    - To view your blog post locally, browse to http://localhost:4000/wildfly-elytron/blog and then click on your post
- Submit a pull request against the develop branch


FROM ruby:2-slim
ENV BUNDLER_VERSION 2.0.2
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        bats \
        build-essential \
        ca-certificates \
        curl \
        libffi7 \
        make \
        shellcheck \
        git-all \
        rsync \
    && gem install bundler:2.0.2 \
    && bundle config --global silence_root_warning 1

COPY entrypoint.sh /

ENTRYPOINT ["sh", "/entrypoint.sh"]

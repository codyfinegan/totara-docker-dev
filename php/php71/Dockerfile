FROM php:7.1-fpm-buster

ARG TIME_ZONE=Pacific/Auckland

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apt-transport-https \
        libgd3 \
        libgd-dev \
        libfreetype6-dev \
        libjpeg-dev \
        libmcrypt-dev \
        libpng-dev \
        libxml2-dev \
        libicu-dev \
        libpq-dev \
        gnupg2 \
        nano \
        vim \
        wget \
        openssl \
        locales \
        tzdata \
        git \
        libzip-dev \
        libmemcached-dev \
        netcat \
        bc \
        ghostscript \
        graphviz \
        aspell \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install -j$(nproc) xmlrpc \
        zip \
        intl \
        soap \
        opcache \
        pdo_pgsql \
        pdo_mysql \
        pgsql \
        mysqli \
        zip \
        exif \
    && docker-php-ext-configure gd \
            --with-freetype-dir=/usr/include/ \
            --with-png-dir=/usr/include/ \
            --with-jpeg-dir=/usr/include/ \
            --with-gd \
    && docker-php-ext-install -j$(nproc) gd

RUN git clone https://github.com/tideways/php-profiler-extension.git \
    && cd php-profiler-extension \
    && phpize \
    && ./configure \
    && make && make install

RUN echo "extension=tideways_xhprof.so" >> /usr/local/etc/php/conf.d/tideways_xhprof.ini

RUN pecl install -o -f redis \
    &&  rm -rf /tmp/pear \
    &&  docker-php-ext-enable redis

RUN pecl install -o -f igbinary \
    &&  rm -rf /tmp/pear \
    &&  docker-php-ext-enable igbinary

RUN pecl install -o -f memcached \
    &&  rm -rf /tmp/pear \
    &&  docker-php-ext-enable memcached

# we need en_US locales for MSSQL connection to work
# we need en_AU locales for behat to work
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    sed -i -e 's/# en_AU.UTF-8 UTF-8/en_AU.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# install mssql extension
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl https://packages.microsoft.com/config/debian/8/prod.list | tee /etc/apt/sources.list.d/mssql-tools.list \
    && apt-get update && ACCEPT_EULA=Y apt-get install -y \
        msodbcsql17 \
        mssql-tools \
        unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

RUN echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bash_profile \
    && echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc

RUN pear config-set php_ini `php --ini | grep "Loaded Configuration" | sed -e "s|.*:\s*||"` system \
    && pecl install sqlsrv-5.6.1 \
    && pecl install pdo_sqlsrv-5.6.1

RUN docker-php-ext-enable sqlsrv.so && docker-php-ext-enable pdo_sqlsrv.so

RUN ln -fs /usr/share/zoneinfo/${TIME_ZONE} /etc/localtime \
    && dpkg-reconfigure --frontend noninteractive tzdata

COPY config/php.ini /usr/local/etc/php/
COPY config/fpm.conf /usr/local/etc/php-fpm.d/zz-totara.conf

# Source each .sh file found in the /shell/ folder, always source the default_aliases.sh file first
RUN echo 'if [[ -e "/root/custom_shell/default-aliases.sh" ]]; then source "/root/custom_shell/default-aliases.sh"; fi' >> ~/.bashrc && \
  echo 'for f in /root/custom_shell/*.sh; do [[ "$f" != "/root/custom_shell/default-aliases.sh" && -e "$f" ]] && source "$f"; done;' >> ~/.bashrc

# Have the option of using the oh my zsh shell.
RUN apt-get update && apt-get install -y zsh
RUN sh -c "$(curl https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)" --unattended
RUN git clone https://github.com/romkatv/powerlevel10k ~/.oh-my-zsh/custom/themes/powerlevel10k
RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions
RUN git clone https://github.com/zsh-users/zsh-completions ~/.oh-my-zsh/custom/plugins/zsh-completions
RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting
RUN echo 'setopt +o nomatch' > ~/.zshrc
RUN echo 'source ~/custom_shell/.zshrc' >> ~/.zshrc
RUN cat ~/.bashrc >> ~/.zshrc

FROM php:8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev unzip curl git && \
    docker-php-ext-install pdo pdo_pgsql && \
    rm -rf /var/lib/apt/lists/*

# Install dd-trace-php
RUN curl -LO https://github.com/DataDog/dd-trace-php/releases/latest/download/datadog-setup.php && \
    php datadog-setup.php --php-bin=all && \
    rm datadog-setup.php

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

COPY composer.json .
RUN composer install --no-dev --optimize-autoloader

COPY . .

# Apache config
RUN a2enmod rewrite
COPY apache.conf /etc/apache2/sites-available/000-default.conf

EXPOSE 8004

# Update Apache to listen on 8004
RUN sed -i 's/Listen 80/Listen 8004/' /etc/apache2/ports.conf

CMD ["apache2-foreground"]

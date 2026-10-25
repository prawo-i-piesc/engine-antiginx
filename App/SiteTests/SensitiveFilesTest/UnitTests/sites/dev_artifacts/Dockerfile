FROM php:8.3-fpm
COPY . /var/www/html
USER www-data
HEALTHCHECK CMD php-fpm -t

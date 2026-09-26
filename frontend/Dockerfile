# --- build ---------------------------------------------------------------------------------
# Debian (glibc) image: TypeScript 7's native compiler has no musl build.
FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# --- serve ---------------------------------------------------------------------------------
# Unprivileged nginx: master and workers run as uid 101 (no root in the running container).
# With HTTPS, the mounted certs/tls.key must be readable by uid 101 (docs/NETWORK_SETUP.md).
FROM nginxinc/nginx-unprivileged:1.27-alpine
USER root
RUN rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/snippets /etc/nginx/certs /etc/nginx/available \
    && chown -R 101:0 /etc/nginx/conf.d && chmod -R g+w /etc/nginx/conf.d
COPY nginx/security-headers.conf nginx/app-locations.conf /etc/nginx/snippets/
COPY nginx/http.conf nginx/https.conf /etc/nginx/available/
USER 101
# NGINX_SITE selects http.conf (default) or https.conf at container start.
# PUBLIC_HTTPS_PORT is the published HTTPS port, used in the HTTP -> HTTPS redirect.
ENV NGINX_SITE=http.conf PUBLIC_HTTPS_PORT=443
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080 8443
CMD ["sh", "-c", "if [ \"$PUBLIC_HTTPS_PORT\" = 443 ]; then P=''; else P=\":$PUBLIC_HTTPS_PORT\"; fi; sed \"s/__HTTPS_PORT__/$P/\" /etc/nginx/available/$NGINX_SITE > /etc/nginx/conf.d/site.conf && exec nginx -g 'daemon off;'"]

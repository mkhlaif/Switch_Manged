# --- build ---------------------------------------------------------------------------------
# Debian (glibc) image: TypeScript 7's native compiler has no musl build.
FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# --- serve ---------------------------------------------------------------------------------
FROM nginx:1.27-alpine
RUN rm /etc/nginx/conf.d/default.conf && mkdir -p /etc/nginx/snippets /etc/nginx/certs
COPY nginx/security-headers.conf nginx/app-locations.conf /etc/nginx/snippets/
COPY nginx/http.conf nginx/https.conf /etc/nginx/available/
# NGINX_SITE selects http.conf (default) or https.conf at container start.
ENV NGINX_SITE=http.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080 8443
CMD ["sh", "-c", "cp /etc/nginx/available/$NGINX_SITE /etc/nginx/conf.d/site.conf && exec nginx -g 'daemon off;'"]

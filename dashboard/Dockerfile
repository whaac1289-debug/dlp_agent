FROM node:20-alpine as build
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json* /app/
RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts; else npm install --ignore-scripts; fi
COPY dashboard/ /app
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html

FROM node:18.16.0-alpine
RUN apk add g++ make py3-pip

WORKDIR /src
ENV RUN_MODE="docker"


ARG GITHUB_TOKEN

COPY package.json ./package.json
COPY package-lock.json ./package-lock.json

RUN npm install

COPY . .
RUN npm run build

ENV NODE_ENV=production

EXPOSE 80

CMD [ "npm", "start" ]
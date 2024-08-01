FROM node:20-alpine3.20

WORKDIR /authBackend

COPY package*.json ./

RUN npm install

# install the bcrypt modules for the machine
RUN npm install bcryptjs

RUN npm install -g nodemon

COPY prisma/schema.prisma prisma/

COPY . .

RUN npx prisma generate

EXPOSE 5050

ENV PORT=5050

CMD ["nodemon", "-L", "index.js"]

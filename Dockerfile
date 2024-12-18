FROM node:20-alpine

WORKDIR /app

# 安装依赖
COPY package*.json ./
RUN pnpm install

# 复制应用代码
COPY . .

# 创建 public 目录
RUN mkdir -p public

EXPOSE 3000

CMD ["node", "app.js"] 
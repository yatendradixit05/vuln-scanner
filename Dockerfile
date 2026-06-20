FROM node:20-bookworm

# Python install karo
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies install karo
COPY engine/requirements.txt ./engine/requirements.txt
RUN pip3 install --break-system-packages -r engine/requirements.txt

# Node dependencies install karo
COPY backend/package*.json ./backend/
RUN cd backend && npm install --production

# Baaki sab code copy karo
COPY backend ./backend
COPY engine ./engine

WORKDIR /app/backend

EXPOSE 10000
CMD ["node", "server.js"]
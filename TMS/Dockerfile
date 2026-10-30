FROM python:3.12-slim
WORKDIR /app
COPY app /app/app
COPY vault /app/vault
EXPOSE 8787
CMD ["python", "app/server.py"]

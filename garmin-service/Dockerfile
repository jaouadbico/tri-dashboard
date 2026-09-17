# Not deployed yet — this is here so the service is ready to ship to
# Fly.io/Render when we get there. Single worker only: see main.py's note
# on PENDING_LOGINS for why (the in-progress MFA state lives in a live
# Python object in this process's memory, not anything portable).
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT} --workers 1"]

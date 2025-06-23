FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY src/vaultwarden_ldap_sync ./vaultwarden_ldap_sync
CMD ["python", "-u", "-m", "vaultwarden_ldap_sync.main"]

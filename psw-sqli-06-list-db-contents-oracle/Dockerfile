FROM python:3.12-slim

LABEL lab.suite="portswigger" \
      lab.topic="sql-injection" \
      lab.id="psw-sqli-06-list-db-contents-oracle" \
      lab.title="SQLi listing database contents on Oracle"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN sed -i 's/$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]

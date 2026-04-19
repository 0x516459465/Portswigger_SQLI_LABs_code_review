FROM python:3.12-slim

LABEL lab.suite="portswigger" \
      lab.topic="sql-injection" \
      lab.id="psw-sqli-11-blind-conditional-responses" \
      lab.title="SQLi blind - conditional responses"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]

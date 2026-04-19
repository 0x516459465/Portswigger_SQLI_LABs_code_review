FROM python:3.12-slim

LABEL lab.suite="portswigger" \
      lab.topic="sql-injection" \
      lab.id="psw-sqli-16-out-of-band" \
      lab.role="oob-recorder"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY oob.py /app/

EXPOSE 5432 8080

CMD ["python", "oob.py"]

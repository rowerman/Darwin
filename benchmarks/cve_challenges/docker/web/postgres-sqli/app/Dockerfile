FROM python:3.11-slim

RUN pip install --no-cache-dir flask psycopg2-binary

ENV PGCLIENTENCODING=BIG5

COPY app.py /app/app.py
RUN echo 'flag{web-07-default}' > /flag.txt && chmod 644 /flag.txt
WORKDIR /app
CMD ["python", "app.py"]

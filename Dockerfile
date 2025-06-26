FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app ./app
COPY private.pem public.pem ./
CMD ["cd" , "app"]
CMD ["python3", "app/main.py"]

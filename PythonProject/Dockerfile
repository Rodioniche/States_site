FROM python:3.13
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY main.py main.py
COPY Dockerfile Dockerfile
EXPOSE 8000


CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]




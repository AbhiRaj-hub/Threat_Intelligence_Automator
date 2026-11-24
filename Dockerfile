FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tia ./tia
COPY config ./config
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "tia"]
CMD ["watch", "--every", "60"]

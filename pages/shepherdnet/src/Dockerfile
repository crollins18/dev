FROM python:3.11-slim

RUN pip install --no-cache-dir ansible

WORKDIR /ansible

COPY requirements.yml .

RUN ansible-galaxy role install -r requirements.yml && \
    ansible-galaxy collection install -r requirements.yml

WORKDIR /src

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
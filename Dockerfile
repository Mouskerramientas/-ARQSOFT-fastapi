
FROM python


WORKDIR /code


COPY ./requirements.txt /code/requirements.txt


RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt


COPY . /code/app

CMD ["fastapi", "run", "app/failures.py", "--port", "80"]
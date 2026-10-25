FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml /tmp/penagent-pyproject.toml
RUN --mount=type=cache,target=/root/.cache/pip python -c "import subprocess,tomllib; deps=tomllib.load(open('/tmp/penagent-pyproject.toml','rb'))['project']['dependencies']; subprocess.check_call(['pip','install','--timeout','90','setuptools>=68','wheel',*deps])"
COPY . /app
RUN pip install --no-deps --no-build-isolation . && useradd --create-home penagent
USER penagent
EXPOSE 9004
CMD ["uvicorn", "interpreter.main:app", "--factory", "--host", "0.0.0.0", "--port", "9004", "--no-access-log"]

# SOC AI Assistant Workshop

The attendee guide is published at [soc-ai-assistant-workshop.readthedocs.io](https://soc-ai-assistant-workshop.readthedocs.io/en/latest/). The same pages are in `guide/`, starting at `guide/index.md`.

- `guide/`: the manual, one page per part.
- `exercises/`: files the exercises tell you to copy.
- `lab/`: the Docker Compose lab, started with `lab/scripts/start.sh`.

Build the guide locally:

```bash
pip install -r requirements.txt
sphinx-build -W guide guide/_build
```

# CR Automation

Drafts a change request from scan results. It is being rebuilt one module at a time.
The previous full version is on the `dev` branch.

| Module | Status |
| --- | --- |
| SonarQube | Prints the quality gate status |
| Anchore | Not implemented yet |
| OWASP | Not implemented yet |

## Run

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in the values
python src/main.py
```

## Add a module

1. Create `src/modules/<name>.py` with a function called `<name>()`.
2. Import it in `src/main.py` and call it from `main()`.

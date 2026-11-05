import os

import requests


def sonarqube():
    url = os.environ["SONAR_URL"].rstrip("/")
    token = os.environ["SONAR_TOKEN"]
    project = os.environ["SONAR_PROJECT"]

    # SonarQube tokens are sent as the basic-auth username with an empty password
    response = requests.get(
        f"{url}/api/qualitygates/project_status",
        params={"projectKey": project},
        auth=(token, ""),
        timeout=60,
    )
    response.raise_for_status()

    status = response.json()["projectStatus"]["status"]
    print(f"SonarQube quality gate for {project}: {status}")

from dotenv import load_dotenv

from modules.anchore import anchore
from modules.owasp import owasp
from modules.sonarqube import sonarqube


def main():
    load_dotenv()
    sonarqube()
    anchore()
    owasp()


if __name__ == "__main__":
    main()

import pathlib
import sys


def main():
    path = str(pathlib.Path(__file__).parent.parent.resolve(strict=True))
    if path not in sys.path:
        sys.path.append(path)


main()

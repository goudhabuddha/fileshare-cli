from typing import Optional
import typer

import user

APP_NAME = 'telepoop'

app = typer.Typer()
app.add_typer(user.app, name='user')


if __name__ == '__main__':
    app()
from typing import Optional
import typer

app = typer.Typer()

@app.command()
def register(
    username: str = typer.Option(...),
    registration_token: str = typer.Option(..., metavar='token', help='Required for registering a new user.'),
    password: str = typer.Option(..., prompt=True, confirmation_prompt=True, hide_input=True, min=8)
):
    pass



if __name__ == "__main__":
    app()
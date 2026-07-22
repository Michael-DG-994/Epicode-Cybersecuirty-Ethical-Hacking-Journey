import secrets

SCELTE = {
    "sasso":"forbice",
    "forbice":"carta",
    "carta":"sasso"
}

SCELTE_VALIDE = list(SCELTE.keys())

def scelta_user():
    while True:
        scelta = input("Scegli tra: Sasso, Carta o Forbice: ").strip().lower()
        if scelta in SCELTE_VALIDE:
            return scelta
        else:
            print("Scelta non valida! prova di nuovo!")

def game(nome:str)->str: 
    user = scelta_user()
    computer = secrets.choice(SCELTE_VALIDE)

    print(f"user: {user}\nVS.\ncomputer: {computer}")

    if user == computer:
        risultato = "Pareggiato :|"
    elif SCELTE[user] == computer:
        risultato = "VINTO :)" 
    else:
        risultato = "perso... :(((("
    
    print(f"{nome} IL risutato è...... hai {risultato}")

while True:
    nome = input("Inserisci il tuo nome: ")
    game(nome)

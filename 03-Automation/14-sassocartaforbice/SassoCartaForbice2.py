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

# Gioco inizia:
while True:
    try:
        numero_partite = int(input("Quante partite vuoi giocare?\nNumero Partite: "))
        if numero_partite < 1:
            print("Numero partite deve essere maggiore di uno!!!")
            continue
        nome = input("Inserisci il tuo nome: ") 
        for numero_partite in range(numero_partite):
            game(nome)
        break
    except ValueError:
        print(f"Numero partite non valido!!! usa un numero intero mbe dai!!!")
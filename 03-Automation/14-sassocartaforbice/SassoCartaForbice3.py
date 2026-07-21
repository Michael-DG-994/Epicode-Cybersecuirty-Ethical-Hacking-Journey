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

def game(nome:str, punteggio_user:int, punteggio_comp=int): 
    user = scelta_user()
    computer = secrets.choice(SCELTE_VALIDE)
    print(f"user: {user}\nVS.\ncomputer: {computer}")
    if user == computer:
        risultato = "Pareggiato :|"
    elif SCELTE[user] == computer:
        risultato = "VINTO :)" 
        punteggio_user += 1
    else:
        risultato = "perso... :(((("
        punteggio_comp += 1
    print(f"{nome} IL risutato è...... hai {risultato}")
    return punteggio_user, punteggio_comp

def sort_leaderboard(leaderboard):
    print("Punteggi leaderboard:\n")
    for giocatore, punti in sorted(leaderboard.items(), key=lambda x: x[1], reverse=True):
        print(f"{giocatore}: {punti}")

# Gioco inizia:
while True:
    try:
        numero_partite = int(input("Quante partite vuoi giocare?\nNumero Partite: "))
        if numero_partite < 1:
            print("Numero partite deve essere maggiore di uno!!!")
            continue
        nome = input("Inserisci il tuo nome: ") 
        punteggio_user=0
        punteggio_comp=0
        for numero_partite in range(numero_partite):
            punteggio_user, punteggio_comp = game(nome,punteggio_user,punteggio_comp)
            leaderboard = {
                nome : punteggio_user,
                "Computer" : punteggio_comp
            }
        sort_leaderboard(leaderboard)
        break
    except ValueError:
        print(f"Numero partite non valido!!! usa un numero intero mbe dai!!!")
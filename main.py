import time
import random
from hashlib import sha512 as H
from Server import Server

if __name__ == '__main__':
    print('Регистрация')
    server = Server()
    ts = int(time.time()) % 10000
    #Безопасное простое
    N = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
    g = 2 #Генератор по модулю N, такой, что g^x % N = X
    I = input('Введите логин: ')
    p = input('Введите пароль: ')
    # x = H(s,p), где H - одностороння Хэш функция, s - соль, p - password
    x = int(H(str(ts).encode() + str(p).encode()).hexdigest(), 16)
    # v - pass verifier
    v = pow(g,x,N)
    # Saving new account
    server.add(I,v,ts)
    print("Регистрация завершена")
    # Безопасность обеспечивается сложностью операции дискретного логарифмирования — получения x из v=g^x%N зная v, g, N.
    while True:
        print('Авторизация')
        email = input('Введите логин:')
        password = input('Введите пароль:')
        emails = list(map(lambda x: x[0], server.database))
        if email not in emails:
            print('Неверный логин или пароль')
            break
        

        # Случайное число
        a = random.randint(10, 100) 
        # На сервер передаётся пара из логина I и полученного A=g^a % N 
        A = pow(g,a,N)
        #Сервер должен убедиться, что А!=0
        #Сервер по полученному логину достаёт верификатор и соль
        verificator = server.database[emails.index(email)][1]
        #Соль
        salt = server.database[emails.index(email)][2] 
        # Random int
        b = random.randint(10, 100)
        # Генерация ещё одного числа, B, которое будет передано сервером на клиент.
        B = (3 * verificator + pow(g,b,N)) % N
        # Обе стороны вычисляют скремблер, u = Hash(A,B)
        u = int(H(str(A).encode() + str(B).encode()).hexdigest(), 16)
        if u == 0:
            print('Соединение разорвано')
            break
        #Общий ключ сессии
        # x = Hash(s,p)
        x = int(H(str(salt).encode() + str(password).encode()).hexdigest(), 16)
        #S1 = ((B - k*(g^x % N)) ^ (a + u*x)) % N
        S1 = pow((B - 3 * pow(g , x , N)), (a + u * x), N)
        #K1 = Hash(S)
        K1 = int(H(str(S1).encode()).hexdigest(), 16)
        #Синанимично для севера
        #S = ((A*(v^u % N)) ^ b) % N
        S2 = pow(A * pow(v , u , N), b, N)
        K2 = int(H(str(S2).encode()).hexdigest(), 16
        #С этого момента у них есть одно и то же число у обоих.
        #Чтобы подтвердить каждый генерирует подтверждение
        #M = Hash( Hash(N) XOR H(g), Hash(I), s, A, B, K)
        # Hash(N) & Hash(g) соответственно
        H_n = int(H(str(N).encode()).hexdigest(), 16)
        H_g = int(H(str(g).encode()).hexdigest(), 16)
        Hn_xor_Hg = H_n ^ H_g
        H_I = int(H(str(email).encode()).hexdigest(), 16)
        M_Client = int(H(str(Hn_xor_Hg).encode() + str(H_I).encode() + str(S1).encode() + str(A).encode() + str(B).encode() + str(3).encode()).hexdigest(), 16)
        M_Server = int(H(str(Hn_xor_Hg).encode() + str(H_I).encode() + str(S2).encode() + str(A).encode() + str(B).encode() + str(3).encode()).hexdigest(), 16)
        #Подтверждение сервером, что клиент легитимен
        if M_Client == M_Server:
            R_Server = int(H(str(A).encode() + str(M_Server).encode() + str(K2).encode()).hexdigest(), 16)
            R_Client = int(H(str(A).encode() + str(M_Client).encode() + str(K1).encode()).hexdigest(), 16)
            print(R_Server == R_Client)
        else:
            print('В доступе отказано')

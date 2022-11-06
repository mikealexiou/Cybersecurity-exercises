from random import choices

characters = list("0123456789abcdefghijklmnopqrstuvwxyz")

password = input("Give password: ")

user_password = ''
while user_password != password:
    user_password = choices(characters, k=len(password))
    print(">>" + str(user_password)+"<<")
    if user_password == list(password):
        print("User password is: " + "".join(user_password))
        break

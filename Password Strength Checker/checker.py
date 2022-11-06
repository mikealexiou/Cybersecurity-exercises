import string

password = input("Enter password: ")

upperCase = any([1 if c in string.ascii_uppercase else 0 for c in password])
lowerCase = any([1 if c in string.ascii_lowercase else 0 for c in password])
symbols = any([1 if c in string.punctuation else 0 for c in password])
numbers = any([1 if c in string.digits else 0 for c in password])



characters_list = [upperCase, lowerCase, symbols, numbers]
length = len(password)


result = 0
with open('passwords.txt','r') as f:
    common = f.read().splitlines()
if password in common:
    print("Password was found in a common list.")
    exit()

if length > 8:
    result += 1
if length > 12:
    result += 1
if length > 17:
    result += 1
if length > 20:
    result += 1

print("Password length is "+str(length)+" ")

if sum(characters_list) > 1:
    result += 1
if sum(characters_list) > 2:
    result += 1
if sum(characters_list) > 3:
    result += 1

print("Password has " + str(sum(characters_list)) + " different character types")
if result < 4:
    print(f"The password is quite weak! ")
elif result == 4:
    print("The password is ok!" )
elif 4 < result <= 6:
    print("The password is pretty good! ")
elif result > 6:
    print("The password is strong! ")

a=input("Enter the email contents: ")
b=list(set(eval(a.strip())))
for i in b:
    print(i, end=";")
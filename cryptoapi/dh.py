
g = 30948595
p = 35435345

a = 12345689
b = 32594830

alice_public = pow(g,a,p)
bob_public = pow(g,b,p)

alice_secret = pow(bob_public, a, p)
bob_secret = pow(alice_public, b, p)

print(alice_secret, bob_secret)

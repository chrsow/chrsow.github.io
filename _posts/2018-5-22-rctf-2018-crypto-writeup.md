---
layout: post
published: true
title: "RCTF 2018 Crypto Writeup"
subtitle:  ""
date: 2018-5-21 10:00:00 +0700
header-img: "/assets/img/posts/rctf18/rctf18-intro.png"
categories: story
tags: [writeup, crypto]
---

There are only two crypto challenges in this CTF event. However, I found that the challenges are interesting to share the writeup and the idea behind the solution for each challenges.

<h2><a name="cpushop"></a><strong>cpushop (176 pt, 94 solved)</strong></h2>
We got the source code and the service to interact with. 
```python
#!/usr/bin/env python
# encoding: utf-8

import random
import string
import signal
import sys
import os
import time
from hashlib import sha256
from urlparse import parse_qsl

os.chdir(os.path.dirname(os.path.abspath(__file__)))
signkey = ''.join([random.choice(string.letters+string.digits) for _ in xrange(random.randint(8,32))])
print len(signkey)
items = [('Intel Core i9-7900X', 999), ('Intel Core i7-7820X', 599), ('Intel Core i7-7700K', 349), ('Intel Core i5-7600K', 249), ('Intel Core i3-7350K', 179), ('AMD Ryzen Threadripper 1950X', 999), ('AMD Ryzen 7 1800X', 499), ('AMD Ryzen 5 1600X', 249), ('AMD Ryzen 3 1300X', 149), ('Flag', 99999)]
money = random.randint(1000, 10000)

def list_items():
    for i,item in enumerate(items):
        print '%2d - %-30s$%d' % (i, item[0], item[1])

def order():
    n = input_int('Product ID: ')
    if n < 0 or n >= len(items):
        print 'Invalid ID!'
        return
    payment = 'product=%s&price=%d&timestamp=%d' % (items[n][0], items[n][1], time.time()*1000000)
    sign = sha256(signkey+payment).hexdigest()
    payment += '&sign=%s' % sign
    print 'Your order:\n%s\n' % payment

def pay():
    global money
    print 'Your order:'
    sys.stdout.flush()
    payment = raw_input().strip()
    sp = payment.rfind('&sign=')
    if sp == -1:
        print 'Invalid Order!'
        return
    sign = payment[sp+6:]
    try:
        sign = sign.decode('hex')
    except TypeError:
        print 'Invalid Order!'
        return

    payment = payment[:sp]
    signchk = sha256(signkey+payment).digest()
    if signchk != sign:
        print 'Invalid Order!'
        return

    for k,v in parse_qsl(payment):
        if k == 'product':
            product = v
        elif k == 'price':
            try:
                price = int(v)
            except ValueError:
                print 'Invalid Order!'
                return

    if money < price:
        print 'Go away you poor bastard!'
        return

    money -= price
    print 'Your current money: $%d' % money
    print 'You have bought %s' % product
    if product == 'Flag':
        print 'Good job! Here is your flag: %s' % open('flag').read().strip()

def input_int(prompt):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        n = int(raw_input())
        return n
    except:
        return 0

def menu():
    print "CPU Shop"
    while True:
        print "Money: $%d" % money
        print "1. List Items"
        print "2. Order"
        print "3. Pay"
        print "4. Exit"
        sys.stdout.flush()
        choice = input_int("Command: ")
        {
                1: list_items,
                2: order,
                3: pay,
                4: exit,
        }.get(choice, lambda *args:1)()
        sys.stdout.flush()

if __name__ == "__main__":
    signal.alarm(60)
    menu()
```
It is the service for cpu shopping, we can pay for the product we ordered. The purpose is to buy the flag which is `$99999` while the maximum money the service can give us is only `$9999`. 

```
$ nc cpushop.2018.teamrois.cn 43000

Money: $8491
1. List Items
2. Order
3. Pay
4. Exit
Command:
```

Take a look at the `Order` option in the service. When we order the product, the service will returns the payment in the format

```
product=[product-name]&price=[product-price]&timestamp=[timestamp]
&sign=[signature]
```

The signature(`sign`) is genereated by $$SHA256(signkey \vert payment)$$. This way of signature generation are well-known to be vulnerable to [Hash Length Extension Attack](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks). Since the service uses `parse_sql` which parses the ***lastest*** parameter in the query in case of there is the duplicate parameter.

For example, we will get `New` instead of `Old`.
```python
product = ''
for k,v in parse_qsl('product=Old&product=New'):
    if k == 'product':
        product = v
print product
# New
```

To get the flag, we will append `&product=Flag` to the payload with hash length extension attack to tell the service that the `product` we want to get is `Flag`, while the price is still the price of the product in the payment we have already ordered (which we have enough money to buy).

Our payload will be something like this 

<pre>
[payment][padding][payment]<b>&product=Flag&sign=[new-signature]</b>
</pre>

Where `[payment]` is the format we got from the order above and append the `[new-signature]` for signature checking process in the service.

However, the key(`signkey`)'s length is required for performing hash length extention attack, but that is not the problem because we know the range of the key's length `[8, 32)` from the source code, just bruteforce it.

I used a cool library [HashPump](https://github.com/bwall/HashPump) for generating our payload for the hash length extension attack.

``` python
import socket
import hashpumpy

HOST = 'cpushop.2018.teamrois.cn'
PORT = 43000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

s.recv(1024)
s.send('2\n') # order
s.recv(1024)
s.send('0\n') # product-id 
order = s.recv(1024).split('\n')[1].strip().split('&sign=')
original_product, sign = order[0], order[1]
add_product = '&product=Flag'
for i in xrange(8, 33): # brute force key length
    res_hash= hashpumpy.hashpump(sign, original_product, original_product + add_product, i)
    new_sign = res_hash[0]
    payload = res_hash[1]
    payload += '&sign=' + new_sign
    s.recv(1024)
    s.send('3\n') # pay
    s.recv(1024)
    s.send(payload + '\n')
    res = s.recv(1024)
    if 'Invalid' not in res:
        print '[+] Attack success'
        print '[+] Key lengh: ' + str(i)
        flag = s.recv(1024).split('flag: ')[1].split('\n')[0]
        print '[*] Flag: ' + flag
        break
```

<strong>Flag: RCTF{ha5h_l3ngth_ex7ens10n_a77ack_1s_ez}</strong>
<br>
<br>
<h2> <a name="ECDH"></a> <strong>ECDH (416 pt, 29 solved)</strong></h2>
This time we don't have any source code given, just only the service. Let's find out about the service.

```
$ nc ECDH.2018.teamrois.cn 42000

Welcome to my GETFLAG system
1. visit Alice
2. visit Bob
3. about
input here:
```
Let's ask for the service's information first.
```
input here: 3
ECDH.....https://github.com/esxgx/easy-ecc..secp128r1..AES...ECB......
```

So we know that the service uses `secp128r1` curve, and `AES ECB` which is the cipher that Bob uses to encrypt the flag with the shared key given from `ECDH` ([Elliptic Curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie-Hellman)) protocol and sends the encrypted flag to Alice.

After visits Alice and Bob, The options we can do with him/her surprised me.

```
input here: 1

Hello nobody...I'm Alice... you can:
1. ask for flag
2. ask me about my public key
3. ask me about Bob's public key
4. tell me Bob's public key
```
We can tell Bob new Alice's public key and vice versa! This sounds familiar with [ECDH man-in-the-middle active attack](https://crypto.stackexchange.com/questions/35603/ecdh-man-in-the-middle-active-attack). 

What we gonna do

1. Perform MITM attack, tell Bob new Alice's public key (which exactly is our public key) and let him encrypt the flag and send to Alice.
2. Ask Alice for encrypted flag. Use the shared key to decrypt it with AES ECB.

From the ECDH protocol, the shared key can be computed with $$d_{Alice} * d_{Bob} * G$$

Where $$d_{Alice}$$ is Alice's private key, $$d_{Bob}$$ is Bob's private key and $$G$$ is the generetor point on the curve. (in this case, `secp128r1`)

Let's begin the attack. We will tell Bob new Alice's public key (yeah, we will tell him our public key instead). For easy computation, I choose the generator point ($$G$$) as my public key. 

From the fact that our public key is the generator point, our private key will becomes $$1$$ (since $$Q_{Attacker} = d_{Attacker} * G$$ and $$ G = 1 * G $$).

So our key pair is $$(1, G)$$, while Alice is $$(d_{Alice}, Q_{Alice})$$ and Bob is $$(d_{Bob}, Q_{Bob})$$. We will tell Bob to update Alice's new public key which is our public key and let him encrypts the flag with that new shared key (in this challenge only Bob has the flag).

New shared key after communicated with Bob will becomes

$$
d_{Attacker} * d_{Bob} * G\\
&= 1 * d_{Bob} * G\\
&= d_{Bob} * G\\
&= Q_{Bob}
$$

Here is the point, our new shared key is just Bob's public key ($$Q_{Bob}$$) and we can easily get the flag by tell Bob to send the flag to Alice, ask Alice for the encrypted flag, then use Bob's public key to decrypt the encrypted flag with `AES` block cipher in `ECB` mode.

``` python
#!/usr/bin/env sage
import socket
from Crypto.Cipher import AES

HOST = 'ECDH.2018.teamrois.cn'
PORT = 42000

# secp128r1
p = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC
b = 0xE87579C11079F43DD824993C2CEE5ED3
E = EllipticCurve(GF(p), [a, b])
G = E(0x161FF7528B899B2D0C28607CA52C5B86, 0xCF5AC8395BAFEB13C02DA292DDED7A83)

def get_enc_flag():
    # get enc flag (ask bob, then ask alice)
    # (without asking bob first, alice will says nothing)
    s.recv(1024)
    s.send('2\n') # ask bob first
    s.recv(1024)
    s.send('1\n')
    s.recv(1024)
    s.recv(1024)
    s.send('1\n') # then ask alice for enc flag
    s.recv(1024)
    s.send('1\n')
    enc_flag = s.recv(1024).split(': ')[1].strip()
    return enc_flag

def get_pubkey(name):
    s.recv(1024)
    if name == 'alice':
        s.send('1\n')
    elif name == 'bob':
        s.send('2\n')
    else:
        print '[-] Make sure get the public key for the right one.'
        exit(1)
    s.recv(1024)
    s.send('2\n')
    pubkey = s.recv(1024).split('pub: ')[1].strip()
    return pubkey

def set_pubkey(name, pubkey):
    global alice_pubkey
    global bob_pubkey
    s.recv(1024)
    if name == 'alice':
        s.send('2\n')
        s.recv(1024)
        s.send('4\n')
        s.recv(1024)
        s.send(pubkey + '\n')
        alice_pubkey = get_pubkey('alice')
    elif name == 'bob':
        s.send('1\n')
        s.recv(1024)
        s.send('4\n')
        s.recv(1024)
        s.send(pubkey + '\n')
        bob_pubkey = get_pubkey('bob')
    else:
        print '[-] Make sure get the public key for the right one.'
        exit(1)

# Modified from https://gist.github.com/kurtbrose/4423605
def point_compress(point):
    x = hex(long(point[0]))
    x = x[2:len(x)-1]
    if len(x) % 2:
        x = '0'+x
    y = long(point[1])
    out = '03' if y & 0x1 else '02'
    out += x
    return out

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

if __name__ == '__main__':
    bob_pubkey = get_pubkey('bob')

    # tell bob to use our pubkey instead of alice's pubkey
    # just use the generator G
    set_pubkey('alice', point_compress(G)) 
    
    enc_flag = get_enc_flag().decode('hex')

    # since we selected generetor(G) as our pubkey
    # so our privkey is 1 (pubkey = privkey*G)
    # shared secret key will be 1*db*Qb = db*Qb = bob's pubkey
    key = bob_pubkey[2:].decode('hex') 
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(enc_flag)
    print flag
```
<strong> Flag: RCTF{UgotTHEpoint} </strong>

<!-- FB Comment -->
<div class="fb-comments" data-href="https://chrsow.github.io{{ page.url }}" data-colorscheme="dark" data-num-posts="4" data-width="100%"></div>
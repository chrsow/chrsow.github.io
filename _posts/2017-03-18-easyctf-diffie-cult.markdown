---
layout: post
published: true
title: Writeup EasyCTF Diffie-Cult 140 
date:   2017-03-18 13:00:00 +0700
categories: story
tags: [writeup, crypto, diffie-hellman]
---

<h2>CTF : EasyCTF (https://www.easyctf.com)</h2>
<h2>Category: Cryptography </h2>
<h2>Score : 140 </h2>

{% highlight code%}
I just intercepted some odd messages.txt. It appears to be a Diffie-hellman protocol, but my math isn't good enough to figure out what the final shared key is. Help!

g^a mod p = 421049228295820
g^b mod p = 105262307073955
p = 442101689710611

{% endhighlight %}

With the title and the given informations above, it is obviously clear that we are playing with 
"Diffie–Hellman key exchange". (You can read on how it works [here][Diffie–Hellman key exchange])

The objective is to find the secret message which is "g^(ab) mod p".
But with [Discrete Logarithm Problem][discrete-log], we can't find it with only "g^a mod p", "g^b mod p" and "p".



With this useful [website][factordb], we got our divisors.

{% highlight code%}

g^a mod p = 421049228295820 = 2^2 · 5 · 17 · 19^3 · 37 · 47^4 
g^b mod p = 105262307073955 = 5 · 17 · 19^3 · 37 · 47^4
p = 442101689710611 = 3 · 7 · 17 · 19^3 · 37 · 47^4

{% endhighlight %}

We will see that not only "p" is not prime, but it has a same common divisor with "g^a mod p" and "g^b mod p".
And the great common divisor(gcd) for these three numbers is 17 · 19^3 · 37 · 47^4 . Now I will assign it to "k".

{% highlight code%}

k = 17 · 19^3 · 37 · 47^4
g^a mod p = 421049228295820 = 2^2 · 5 · k = 20k
g^b mod p = 105262307073955 = 5 · k = 5k
p = 442101689710611 = 3 · 7 · k = 21k

{% endhighlight %}

Let's consider "g^a mod p".

{% highlight code%}
g^a mod 21k = 20k = -k [since 20k mod 21k = -k]
==> (g^a)^b mod 21k = (-k)^b
==> g^(ab) mod p = (-k)^b [since p = 21k]
{% endhighlight %}

Without knowing for "b" value. We just investigate behaviors for the results of a modulo operation.

{% highlight code%}
(-k)^1 mod p = 421049228295820
(-k)^2 mod p = 42104922829582
(-k)^3 mod p = 357891844051447
(-k)^4 mod p = 168419691318328
(-k)^5 mod p = 105262307073955
(-k)^6 mod p = 231577075562701
(-k)^7 mod p = 421049228295820  [Hmm?, it is the same value for (-k)^1 mod p]
...

{% endhighlight %}

And yes, it is a loop. The answer must be one of these six. Luckiliy, it is the first one.

<i>Flag : 421049228295820 </i>
<br>

<!-- FB Comment -->
<div class="fb-comments" data-href="https://chrsow.github.io{{ page.url }}" data-colorscheme="dark" data-num-posts="4" data-width="100%"></div>

[discrete-log]: https://en.wikipedia.org/wiki/Discrete_logarithm
[factordb]: http://www.factordb.com/
[Diffie–Hellman key exchange]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange

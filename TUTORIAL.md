# Building a Discreet Log Contract Oracle in .NET Core

In 2017, [Tadge Dryja](https://twitter.com/tdryja) published a [paper](https://adiabat.github.io/dlc.pdf) on Discreet Log Contracts. 

By creating a Discreet Log Contract, Alice can form a contract paying Bob some time in the future, based on preset conditions, without committing any details of those conditions to the blockchain. Therefore it is discreet in the sense that no external observer can learn its existence from the public ledger. This contract depends on an external entity or entities publishing a signed message at some point in the future (before the expiration of the contract). The contents of this signed message determine the division of the funds committed to the contract. This external entity is called an “oracle”. Using Discreet Log Contracts, the signature published by the oracle gives each participant of the contract the possibility to claim the amount from the contract that is due him without the need for cooperation from the other party. 

This tutorial will describe you how to build a Discreet Log Contract "oracle". This tutorial describes how to do this in .NET Core, but you can also use [Go](https://github.com/mit-dci/dlc-oracle-go/blob/master/TUTORIAL.md) or [NodeJS](https://github.com/mit-dci/dlc-oracle-nodejs/blob/master/TUTORIAL.md)

### Set up a new project

Firstly, set up a new empty project and include the correct libraries. We start by creating the project folder and add the main program file to it.

```bash
cd ~
mkdir tutorial
cd tutorial
dotnet new console
dotnet add package Mit.Dci.DlcOracle
```

### Generate and save the oracle's private key

Next, we'll need to have a private key. This private key is used in conjunction with a unique one-time-signing key for each message. The private key of the oracle never changes, and its public key is incorporated into Discreet Log Contracts that people form. So if we lose access to this key, people's contracts might be unable to settle. In this example, we'll store the key in a simple format on disk. This is not secure, and should not be considered for production scenarios. However, to illustrate the working of the library it is sufficient.

So we add a function to the `Program.cs` file:

```C#
static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        
static byte[] GetOrCreateKey() {
    byte[] privKey;
    if(File.Exists("privkey.hex")) {
        privKey = File.ReadAllBytes("privkey.hex");
    } else {
        privKey = new byte[32];
        rngCsp.GetBytes(privKey);
        File.WriteAllBytes("privkey.hex", privKey);
    }
    return privKey;
}
```

and then we adjust the `Main()` function to use it, add a global variable to keep the key in, and add the necessary imports:

```C#
using System;
using System.IO;
using System.Security.Cryptography;

namespace tutorial
{
    class Program
    {
        static byte[] privateKey;
        static void Main(string[] args)
        {
            privateKey = GetOrCreateKey();
        }
        (...)
    }
}
```

### Derive and print out the public key

Next, we'll use the DLC library to generate the public key from the private key and print it out to the console:

```C#
(...)
using Mit.Dci.DlcOracle;

(...)

        static void Main(string[] args)
        {
            (...)
            byte[] pubKey = Oracle.PublicKeyFromPrivateKey(privateKey);
            Console.WriteLine("Oracle Public Key: {0}", 
                                BitConverter.ToString(pubKey).Replace("-",""));
        }
(...)
```

In your terminal window, run the application:

```bash
dotnet run
```

The program should show an output similar to this:

```
Oracle Public Key: 027CB3E5C013B9B0E7108D61301B83A9C97E544BDA404446EA39DB323A5BBDC044
```

### Create a loop that publishes oracle values

Next, we'll add a loop to the oracle that will take the following steps:

* Generate a new one-time signing key
* Print out the public key to that signing key (the "R Point")
* Wait 1 minute
* Sign a random numerical value with the one-time key 
* Print out the value and signature

Using the oracle's public key and the "R Point" (public key to the one-time signing key), people can use LIT to form a Discreet Log Contract, and use your signature when you publish it to settle the contract.

So for a regular DLC use case, you would publish your oracle's public key and the R-point for each time / value you will publish onto a website or some other form of publication, so that people can obtain the keys and use them in their contracts. When the time arrives you have determined the correct value, and sign it, you publish both the value and your signature so the contract participants can use those values to settle the contract.

As for the one-time signing key, this has the same security requirements as the oracle's private key. If this key is lost, contracts that depend on it cannot be settled. It is therefore important to save this key somewhere safe. Just keeping it in memory as we do in this example is not good practice for production scenarios. 

One last note on the one-time signing key: The reason that it's named this, is that you can only use it once. Even though there's no technical limitation of you producing two signatures with that key, doing so using the signature scheme DLC uses will allow people to derive your oracle's private key from the data you published.

OK, back to the code. So, first we add the generation of the one-time signing key and printing out the corresponding public key (R Point) in a loop with a minute timeout. This wait period is to simulate the time between announcing your public keys and publishing the actual value. In this time people will form contracts that use the values.

If you want to wait less than a minute, decrease the 60000 (millisecond) value passed to `Thread.Sleep`.

```C#
(...)
using System.Threading;

(...)

        static void Main(string[] args)
        {
            (...)
            
            while(true) {
                byte[] oneTimeSigningKey = Oracle.GenerateOneTimeSigningKey();
                byte[] rPoint = Oracle.PublicKeyFromPrivateKey(oneTimeSigningKey);
                Console.WriteLine("R-Point for next publication: {0}", BitConverter.ToString(rPoint).Replace("-",""));
               
                Thread.Sleep(60000);
            }
        }
(...)
```

Go ahead and run it again. You'll see an output similar to this:

```
Oracle Public Key: 027CB3E5C013B9B0E7108D61301B83A9C97E544BDA404446EA39DB323A5BBDC044
R-Point for next publication: 029FE7E786E4AE74E0A07C968929E1C366D1E049DD0BFA34B758CC60A7582A0290
```

Next step is to actually generate a random value, sign it, and then print the signature and value. 

Using the DLC library, signing values is quite easy:

```C#
(...)
        static Random rand = new Random();

        static void Main(string[] args)
        {
            (...)
            
            while(true) {
                (...)
                Thread.Sleep(60000);

                // Value is a random number between 10000 and 20000
                long value = rand.Next(10000,20000);

                // Generate message to sign. Uses the same encoding as expected by LIT when settling the contract
                byte[] message = Oracle.GenerateNumericMessage(value);
                
                // Sign the message
                byte[] signature = Oracle.ComputeSignature(privateKey, oneTimeSigningKey, message);
               
                Console.WriteLine("Value: {0}\r\nSignature: {1}", value,
                                BitConverter.ToString(signature).Replace("-",""));
                
            }
        }
(...)
```

Next, run your code again. It will print out something like this (you'll have to wait 60 seconds for the value to be published, unless you decreased the `Thread.Sleep` parameter).

```
Oracle Public Key: 027CB3E5C013B9B0E7108D61301B83A9C97E544BDA404446EA39DB323A5BBDC044
R-Point for next publication: 02DCFB940A159A5754A757A61A305041863F95291597D9DF046A4D1E1D1F58424D
Value: 12320
Signature: 7514A288466BB9B05F0A971BAF575FA53AC40943D10E236261A9029DEE9D2C0B
R-Point for next publication: 0382270D1D0D2BE2D5B80339165629C0E52B1385154B64E491711BA90ACAEA978C
```

### Done!

And that's all there is to it. Next steps you could take involve changing how you secure the private key(s), how you publish your public key and the R-points (to something other than your console), and to sign actual real-world values using this set-up. If you publish interesting data feeds using this mechanism, people can base real Discreet Log Contracts on them. If you created any cool oracles, feel free to send a pull request to our [samples repository](https://github.com/mit-dci/dlc-oracle-dotnet-samples) so we can include them for other people to enjoy. You'll also find the complete code for this tutorial there as [one of the samples](https://github.com/mit-dci/dlc-oracle-dotnet-samples/tree/master/tutorial)
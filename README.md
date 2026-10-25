# InkTrace

Leak tracing using invisible text watermarks. This is our term project for the Information Security course at FAST NUCES Lahore.

## About

Say you share a confidential text with ten people and it ends up somewhere it shouldn't. InkTrace lets you find out whose copy it was.

Before sending, each person gets their own copy with a short code hidden in it. The code is made of zero-width Unicode characters, so you can't see it and every copy looks the same. Later, if a copy leaks, you paste it into InkTrace and it reads the code back and tells you who it was given to.

The codes are signed with HMAC-SHA256 using a key that only the sender has. This means a recipient can't change their code to make it look like someone else leaked it. If a signature doesn't check out, the tool reports possible tampering and doesn't accuse anyone.

## Testing

We also want to see how easy it is to beat our own watermark. So far the plan is to:

- paste the text into WhatsApp, Google Docs, Word and Gmail
- copy only part of it
- retype it by hand
- remove the hidden characters with a script
- try to fake a code without the key

We'll put the results here once we have them.

## Tech

Python 3 with the built-in `hmac`, `hashlib` and `sqlite3` modules. There will be a command-line tool and a small web page for the class demo.

## Team

- Arham Basit (23L-3016)
- Muhammad Hassaan Moazan (23L-3003)
- Yasir Zafar (23L-3029)

## Status

The proposal is done and we've just started on the code.

# Poking around Bubble.io applications

## Disclaimer

This repository contains a Python script for extracting data from Bubble.io applications. I'm not responsible for any misuse of this script. Use it at your own risk.

## Introduction

If you don't know what Bubble.io is, it's a no-code platform that allows users to build web applications visually. However, have you ever wondered how secure these applications are? You would be surprised to find out that many Bubble.io apps can be exploited to extract sensitive data!

## Why's that?

Because of the way Bubble.io (or even other no-code platforms) is designed, many crucial operations, including database queries, are handled client-side. This means that if you spend enough time to figure out how they're doing it, you can manipulate these operations to your advantage.

Bubble.io themselves are very aware of these issues, but they don't enforce any security measures. Here's a quote from their [documentation](https://manual.bubble.io/help-guides/data/the-database/protecting-data-with-privacy-rules):

> Bubble has strong security features in place, but we don't enforce them. It's up to you as the developer of the app to use them in the right way to make sure your user's private data stays private.

Guess what? Many developers don't use or care about these "security features". (The "security features" being only their "Privacy Rules" feature.)

Did you also know that almost any Bubble.io app has a [publicly accessible API endpoint](https://forum.bubble.io/t/easy-file-upload-to-bubble-using-api-fileupload/323804) that lets you upload anything to their database? More on that later.

## Part I: Extracting data from Bubble.io apps

Every Bubble.io app has an endpoint that is used to fetch data from the database that is used internally by the client-side code. This endpoint is `(BASE URL)/elasticsearch/msearch`. There are other endpoints for manipulating data, but this one is the one we are interested in.

This endpoint accepts a POST request with a payload of a JSON object that contains the query to be executed. The query is encoded using a function called `encode_data`, which is defined in the client-side code.

If we inspect the client-side code, we can find the definition of this function. It's surprisingly easy to find (you can also find it via the Initiator tab on Network, if you know where to look), since the code is not obfuscated at the point where no one can read it.

```javascript
var encode_data, init_obfuscate = __esm({
'lib-browser/db/obfuscate.js'() {
  'use strict';
  init_define_process_env();
  init_shim();
  init_aes();
  init_pbkdf2();
  init_md5();
  init_utils();
  init_base64();
  init_obfuscate_shared();
  encode_data = encode_data_raw(encode3)
}
```

As you can see, encode_data is actually just a wrapper around another function. `encode_data_raw`, which takes another function `encode3` as an argument. This function is also defined in the same file.

```javascript
encode_data_raw = encode4 => (data, appname) => {
  let v = '1',
  cur_timestamp = String(timestamp()),
  timestamp_version = `${ cur_timestamp }_${ v }`,
  key = appname + cur_timestamp,
  iv = String(Math.random()),
  encoded = {
    z: encode4(key, iv, JSON.stringify(data), appname),
    y: encode4(appname, 'po9', timestamp_version, appname),
    x: encode4(appname, 'fl1', iv, appname)
  };
  return client_config_default2.debug_unobfuscated_client_queries &&
  (encoded.__debug_raw = data),
  encoded
}
```

If you take a closer look, you'll see that this function takes the data (the query) and the app name as arguments. It then generates a timestamp and some other values, and finally calls the `encode3` function to encode the data.

```javascript
function encode3(key, iv, text2, appname) {
  let derivedKey = pbkdf2(md5, key, appname, {
    c: 7,
    dkLen: 32
  }),
  derivedIv = pbkdf2(md5, iv, appname, {
    c: 7,
    dkLen: 16
  }),
  output3 = cbc(derivedKey, derivedIv, {
    disablePadding: !1
  }).encrypt(utf8ToBytes(text2));
  return gBase64.fromUint8Array(output3)
}
```

This function uses PBKDF2 with MD5 as the hashing algorithm to derive a key and an IV from the provided key and IV. It then uses these derived values to encrypt the data using AES in CBC mode. The final output is then encoded in Base64.

It's not really supposed to be secure, since the key and IV are derived from values we can easily obtain (the app name and a random value). This is only a mild obfuscation.

With the knowledge of how the encoding works, we can easily replicate this function and encode our own queries, and send them to the `msearch` endpoint to extract data from the database.

This is the query format that the `msearch` endpoint expects:

```python
data = {
    "appname": appname,
    "app_version": app_version,
    "searches": [
        {
            "appname": appname,
            "app_version": app_version,
            "type": f"custom.{user_type}" if user_type != 'user' else user_type,
            "constraints": [], # usually contains filters here, but we're ommitting it to get all the data
            "sorts_list": [],
            "from": offset,
            # maybe can be omitted
            "search_path": "{\"constructor_name\":\"State\",\"args\":[{\"type\":\"json\",\"value\":\"%p3.bTGbC.%el.cnvDO2.%el.cntLz1.%el.cntRQ.%el.cntTS.%el.cntNC1.%s.0\"}]}",
            "situation": "initial search",
            "n": 1000 # bubble truncates to 400 if higher than that
        }
    ]
}
```

<sub>**Note**: You can only get up to 50k records this way, probably there's a workaround for this, but I'm not aiming to get everything from an app, just enough to prove the point.</sub>

You may ask, don't you still need the data types and structure of the database to be able to query it?

Yes, you do, but you can easily check them by just typing `window.app` in the browser console. If you inspect a little further in the HTML that the average Bubble.io app has, you'll see that there's a script that dynamically sets `window.app` to a JSON object that contains the data types and structure of the database.

With all this information, you can pretty much extract any data you want. Right?

...and that's exactly what this repository has done. It contains a Python script that replicates the encoding function and allows you to send queries to the `msearch` endpoint. In bulk. Yes. You can extract all the data from an app if you want to.

For fun, I did it with Bubble.io themselves. There isn't that much data, since they actually enforce security measures, but I was able to extract the whole plugin catalog, along with their reviews, for example. There's a copy of the data in this repository.

## Part II: Enabling the debugger in any app

Every Bubble.io app has a built-in debugger that allows you to inspect elements, workflows (step-by-step), and among other things. However, this debugger is only available to the app owner and collaborators. But, with a little bit of patching, we can enable the debugger in any app.

I did it with [an extension](https://github.com/Nightdavisao/bubblepwn). Only works in Firefox for now. And no, there's no compiled version, you have to build it yourself.

## Part III: Uploading files to any Bubble.io app

WIP.

## Related projects

* [pop_n_bubble](https://github.com/demon-i386/pop_n_bubble) - A GitHub repository that also explores this issue, which I didn't know about until after I made this.

# orbicfg
orbicfg is a tool that can decrypt and encrypt configuration backups for Orbi routers (and some other Netgear devices).

## Usage

### Decrypt

```
./orbicfg -decrypt NETGEAR_Orbi.cfg -out decrypted.json
```

If successful, the `config` JSON object of `decrypted.json` will contain all the key-value pairs of your device config. The `metadata` object **should not be modified**, as it contains important information that orbicfg needs for re-encryption (see [Wrapper Format](#wrapper-format)).

### Encrypt

After editing `decrypted.json` as desired:

```
./orbicfg -encrypt decrypted.json -out NETGEAR_Orbi_modified.cfg
```

You should then be able to restore `NETGEAR_Orbi_modified.cfg` to your device and see the changes take effect.

## Wrapper Format

orbicfg decrypts configs into a JSON wrapper instead of their raw representation, which is technically a binary format (albeit a readable one).

By default, the JSON wrapper may look like:

```json
{
    "metadata": {
        "header_offset": 655360,
        "stated_magic": 538120740,
        "real_magic": 538120740,
        "rng": "uclibc"
    },
    "config": {
        "qos_list60": "Unreal-Tourment 1 Unreal-Tourment 1 UDP 7777,27960 7783,27960 ---- ----",
        ...
    }
}
```

Note that the wrapper includes several pieces of metadata (which you should not edit in 99% of use cases) and the device's config entries formatted as a JSON dictionary. It's structured like this for two main reasons:

1. The metadata would be cumbersome to pass manually on the CLI every time you want to re-encrypt a file. So, to make your life easier, it's baked into the wrapper format.

2. A JSON config is less error-prone to edit than a binary file (for one, syntax errors will be caught). I have no idea how brittle Netgear's config parsing code is, and I don't care to find out. I want to make it as hard as possible for you to accidentally brick your device.

### Raw Mode

Some users may want to work with the raw bytes of the decrypted config instead of a JSON dictionary representation of the entries. If you have a need for this, and you accept the risk of potentially irreversible damage to your device if something goes awry, you can use the `-raw` flag during decryption. This tells orbicfg to place the raw config bytes into a Base64-encoded field called `config_raw`. In this mode, the decrypt output looks like:


```json
{
  "metadata": {
    "header_offset": 655360,
    "stated_magic": 538120740,
    "real_magic": 538120740,
    "rng": "uclibc"
  },
  "config_raw": "cW9zX2xpc3Q2M..."
}
```

To edit the raw config, you'll first need to Base64-decode `config_raw` (e.g., `jq -r .config_raw < decrypted.json | base64 -d > config_decoded`). To re-encrypt it, you'll have to Base64-encode your edited `config_decoded` file and place the contents back into the `config_raw` field.

## FAQ

Q. orbicfg isn't working/is returning an error. Help!

A. Universal device support turns out to be pretty hard because certain ones have quirks (likely bugs in Netgear's code) that require manual investigation to work around. If you [open an issue](https://github.com/Fysac/orbicfg/issues/new) with the exact command you ran, the error message, your device model, and its firmware version, I'll take a look as soon as I can.

Q. I fixed a bug/added support for a device. How do I contribute? 

A. Feel free to [open a pull request](https://github.com/Fysac/orbicfg/pulls).

## Encryption Scheme

This section is for those curious about how Netgear implemented config encryption; you can safely ignore it if you just want to use the tool. Some details in the text below may be outdated, as it was written based on the now-ancient RBR50, but it should remain broadly true.

Configuration backups and restores are handled by the `/bin/datalib` program. When creating a backup, `datalib` encrypts the raw key-value pairs of the router's configuration using a [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher). It generates the keystream by seeding uClibc's (musl libc's on more recent devices) [`rand(3)`](https://man7.org/linux/man-pages/man3/rand.3.html) implementation with a hardcoded integer and successively calling `rand()` for every 4 bytes of the plaintext. The seed value is also included in the header of the encrypted backup, giving end users all the information they need to decrypt it.


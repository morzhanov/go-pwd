# go-pwd

Tool to encode/decode passwords

## Encryption

```shell
gpwd enc
```

It will prompt to provide secret and password

## Decryption

```shell
gpwd dec
```

It will prompt for secret and after that password will be printed out

## Building and adding to PATH (fish)

1. **Compile your Go script into a binary**:

   Compile your script into a binary by running:

    ```shell
    go build . -o gpwd
    ```
   
    Or

    ```shell
   make build
    ```

2. **Move the binary to a directory in your PATH**:

   Create a directory for your custom binaries. You can create a `bin` directory in your home directory:

    ```shell
    mkdir ~/bin
    ```

   Move the `gpwd` binary to this directory:

    ```shell
    mv gpwd ~/bin
    ```

3. **Add the directory to your PATH in Fish shell**:

   Open your Fish shell configuration file `~/.config/fish/config.fish`:

    ```shell
    nano ~/.config/fish/config.fish
    ```

   Add the following line to this file to include the `bin` directory in your PATH:

    ```shell
    set -gx PATH $HOME/bin $PATH
    ```

   Save the changes to the configuration file.

4. **Reload Fish configuration**:

   After saving the changes, reload your Fish configuration to apply the changes:

    ```shell
    source ~/.config/fish/config.fish
    ```

5. **Test your setup**:

   You should now be able to run `gpwd` from anywhere in your terminal, and it should execute your `gpwd` script.

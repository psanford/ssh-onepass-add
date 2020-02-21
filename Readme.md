# ssh-onepass-add

Add password protected ssh keys to your ssh-keying using passwords stored in 1password.

This tool depends on 1password's command line tool "op".

## Usage

    eval $(op signin domain)
    ssh-onepass-add --public-key 'SHA256:K9iDay9EhqzjORPiV7gBuk2Fi7ip/EFpFv+adJOl/+A' --pw-name 'Name of my password in 1pw'

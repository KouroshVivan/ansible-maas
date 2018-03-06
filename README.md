# ansible-maas

An Ansible Dynamic Inventory Script for the Ubuntu MAAS 2.0 API.

Primarily it will be called by Ansible itself with the `--list` or `--host`
arguments, but additional arguments were implemented for administrators to take
advantage of if desired.

Note: this script will only return machines that are in "Deployed" status.

## Usage

- Replace Ansible's hosts file in the correct directory, e.g. `/etc/ansible/hosts`
- Set environment variables:
  - `MAAS_IP` ip of maas server and `MAAS_USER` user having .maaskey in his home folder
  - OR set directly
    - `MAAS_URL`, ex: "http://127.0.0.1:5240/MAAS/api/2.0"
    - `MAAS_TOKEN` maas token
- Enjoy!

